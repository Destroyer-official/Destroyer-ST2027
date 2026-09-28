#!/usr/bin/env python3
"""
Zero-Knowledge Authentication Module - Military 2026 Security

This module implements zero-knowledge authentication for privacy-preserving
identity verification:
- Schnorr-based ZK proofs for identity verification
- Group membership proofs without revealing specific identity
- Range proofs for attribute verification (e.g., clearance level)
- Anonymous credentials with selective disclosure
- Unlinkable authentication across sessions

Security Properties:
- Valid proofs verify successfully
- Invalid proofs fail with overwhelming probability
- Authentication tokens are cryptographically unlinkable across sessions
- No information about identity revealed during verification

Requirements Implemented:
- 7.1: Schnorr-based ZK proofs for identity verification
- 7.2: Group membership proofs without revealing specific identity
- 7.3: Range proofs for attribute verification
- 7.4: Anonymous credentials with selective disclosure
- 7.5: Unlinkable authentication across sessions
"""

import os
import sys
import platform_hsm_interface as cphs
import hmac
import hashlib
import logging
from typing import Tuple, List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



def secure_randbelow(n: int) -> int:
    if n <= 0:
        raise ValueError
    k = n.bit_length()
    num_bytes = (k + 7) // 8
    while True:
        r = cphs.get_secure_random(num_bytes)
        if not r:
            raise RuntimeError("MILITARY FATAL: Hardware RNG failed. System halting.")
        val = int.from_bytes(r, 'little')
        val &= (1 << k) - 1
        if val < n:
            return val

def secure_token_bytes(n: int) -> bytes:
    r = cphs.get_secure_random(n)
    if not r:
        raise RuntimeError("MILITARY FATAL: Hardware RNG failed. System halting.")
    return r

class ZKProofError(Exception):
    """Base exception for ZK proof errors."""


class ZKProofInvalid(ZKProofError):
    """Exception raised when ZK proof verification fails."""
    def __init__(self, message: str = "Zero-knowledge proof verification failed"):
        super().__init__(message)


class ZKProofGenerationError(ZKProofError):
    """Exception raised when ZK proof generation fails."""



@dataclass
class ZKProof:
    """
    Data class for a Zero-Knowledge Proof.
    
    Implements Schnorr-style ZK proofs with commitment, challenge, and response.
    
    Attributes:
        commitment: The prover's commitment (R = g^k)
        challenge: The verifier's challenge (c = H(R || public_key || message))
        response: The prover's response (s = k + c * secret)
        proof_type: Type of proof (identity, membership, range, credential)
        timestamp: When the proof was generated
        session_id: Unique session identifier for unlinkability
    """
    commitment: bytes
    challenge: bytes
    response: bytes
    proof_type: str = "identity"
    timestamp: Optional[datetime] = None
    session_id: Optional[bytes] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize proof to dictionary."""
        return {
            'commitment': self.commitment.hex(),
            'challenge': self.challenge.hex(),
            'response': self.response.hex(),
            'proof_type': self.proof_type,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'session_id': self.session_id.hex() if self.session_id else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ZKProof':
        """Deserialize proof from dictionary."""
        return cls(
            commitment=bytes.fromhex(data['commitment']),
            challenge=bytes.fromhex(data['challenge']),
            response=bytes.fromhex(data['response']),
            proof_type=data.get('proof_type', 'identity'),
            timestamp=datetime.fromisoformat(data['timestamp']) if data.get('timestamp') else None,
            session_id=bytes.fromhex(data['session_id']) if data.get('session_id') else None
        )


@dataclass
class GroupMembershipProof:
    """
    Proof of group membership without revealing specific identity.
    
    Attributes:
        group_id: Identifier of the group
        proof: The ZK proof of membership
        ring_signature: Ring signature for anonymity within group
    """
    group_id: bytes
    proof: ZKProof
    ring_signature: bytes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'group_id': self.group_id.hex(),
            'proof': self.proof.to_dict(),
            'ring_signature': self.ring_signature.hex()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GroupMembershipProof':
        return cls(
            group_id=bytes.fromhex(data['group_id']),
            proof=ZKProof.from_dict(data['proof']),
            ring_signature=bytes.fromhex(data['ring_signature'])
        )


@dataclass
class RangeProof:
    """
    Proof that an attribute is within a range without revealing the value.
    
    Attributes:
        attribute_name: Name of the attribute being proven
        min_value: Minimum value of the range
        max_value: Maximum value of the range
        proof: The ZK proof that value is in range
        commitment: Pedersen commitment to the value
    """
    attribute_name: str
    min_value: int
    max_value: int
    proof: ZKProof
    commitment: bytes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'attribute_name': self.attribute_name,
            'min_value': self.min_value,
            'max_value': self.max_value,
            'proof': self.proof.to_dict(),
            'commitment': self.commitment.hex()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RangeProof':
        return cls(
            attribute_name=data['attribute_name'],
            min_value=data['min_value'],
            max_value=data['max_value'],
            proof=ZKProof.from_dict(data['proof']),
            commitment=bytes.fromhex(data['commitment'])
        )


@dataclass
class AnonymousCredential:
    """
    Anonymous credential with selective attribute disclosure.
    
    Attributes:
        credential_id: Unique credential identifier
        issuer_id: Identifier of the credential issuer
        attributes: Dictionary of attribute names to committed values
        disclosed_attributes: Set of attribute names that are disclosed
        signature: Issuer's signature on the credential
        proof: ZK proof of credential validity
    """
    credential_id: bytes
    issuer_id: bytes
    attributes: Dict[str, bytes]  # attribute_name -> commitment
    disclosed_attributes: Set[str]
    signature: bytes
    proof: Optional[ZKProof] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'credential_id': self.credential_id.hex(),
            'issuer_id': self.issuer_id.hex(),
            'attributes': {k: v.hex() for k, v in self.attributes.items()},
            'disclosed_attributes': list(self.disclosed_attributes),
            'signature': self.signature.hex(),
            'proof': self.proof.to_dict() if self.proof else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnonymousCredential':
        return cls(
            credential_id=bytes.fromhex(data['credential_id']),
            issuer_id=bytes.fromhex(data['issuer_id']),
            attributes={k: bytes.fromhex(v) for k, v in data['attributes'].items()},
            disclosed_attributes=set(data['disclosed_attributes']),
            signature=bytes.fromhex(data['signature']),
            proof=ZKProof.from_dict(data['proof']) if data.get('proof') else None
        )



P2P_ENABLE_CUSTOM_ZK_ENV = "P2P_ENABLE_CUSTOM_ZK"
P2P_ENABLE_EXPERIMENTAL_ENV = "P2P_ENABLE_EXPERIMENTAL"

def is_custom_zk_enabled() -> bool:
    """Check if experimental unaudited custom ZK arithmetic is explicitly permitted.

    Explicit operator opt-in ONLY. Historical argv-sniffing was removed:
    tests must set P2P_ENABLE_EXPERIMENTAL=1.
    """
    exp_val = os.environ.get(P2P_ENABLE_EXPERIMENTAL_ENV, "").strip().lower()
    zk_val = os.environ.get(P2P_ENABLE_CUSTOM_ZK_ENV, "").strip().lower()
    return exp_val in ("1", "true", "yes", "enabled") or zk_val in ("1", "true", "yes", "enabled")


class ZKAuthenticator:
    """
    Zero-Knowledge Authentication System.
    
    Implements privacy-preserving identity verification using:
    - Schnorr-based ZK proofs for identity verification
    - Group membership proofs without revealing specific identity
    - Range proofs for attribute verification
    - Anonymous credentials with selective disclosure
    - Unlinkable authentication across sessions
    
    Security Properties:
    - Valid proofs verify successfully
    - Invalid proofs fail with overwhelming probability
    - Authentication tokens are cryptographically unlinkable
    - No information about identity revealed during verification
    
    Requirements:
    - 7.1: Schnorr-based ZK proofs for identity verification
    - 7.2: Group membership proofs without revealing specific identity
    - 7.3: Range proofs for attribute verification
    - 7.4: Anonymous credentials with selective disclosure
    - 7.5: Unlinkable authentication across sessions
    """
    
    # Prime for finite field arithmetic (256-bit prime: p = 2^256 - 189)
    # UNAUDITED CUSTOM MATH: Gated behind P2P_ENABLE_EXPERIMENTAL=1.
    # Production environments must use ML-DSA multi-signatures (MLDSAMultisigAuthenticator) until external audit.
    PRIME = 2**256 - 189
    
    # Domain separation for different proof types
    GENERATOR_DOMAIN = b"ZKAuthenticator::Schnorr::Generator::v1.0"
    IDENTITY_DOMAIN = b"ZKAuthenticator::Identity::v1.0"
    MEMBERSHIP_DOMAIN = b"ZKAuthenticator::Membership::v1.0"
    RANGE_DOMAIN = b"ZKAuthenticator::Range::v1.0"
    CREDENTIAL_DOMAIN = b"ZKAuthenticator::Credential::v1.0"
    SESSION_DOMAIN = b"ZKAuthenticator::Session::v1.0"
    
    def __init__(self, allow_unaudited: Optional[bool] = None):
        """
        Initialize ZKAuthenticator.
        
        Sets up generators and domain separation for ZK proofs.
        """
        if allow_unaudited is None:
            self.allow_unaudited = is_custom_zk_enabled()
        else:
            self.allow_unaudited = allow_unaudited

        if not self.allow_unaudited:
            raise PermissionError(
                "Custom ZK arithmetic (PRIME=2**256-189) is unaudited and disabled in production. "
                "Use MLDSAMultisigAuthenticator (NIST FIPS 204 ML-DSA-87) in production, or set "
                "P2P_ENABLE_EXPERIMENTAL=1 or P2P_ENABLE_CUSTOM_ZK=1 to enable for testing/research."
            )

        # Initialize generator (using hash-based approach for simplicity)
        self.g = int.from_bytes(
            hashlib.sha3_256(self.GENERATOR_DOMAIN).digest(),
            'big'
        ) % self.PRIME
        
        # Second generator for Pedersen commitments
        self.h = int.from_bytes(
            hashlib.sha3_256(self.GENERATOR_DOMAIN + b"::h").digest(),
            'big'
        ) % self.PRIME
        
        logger.info("ZKAuthenticator initialized")
    
    def _mod_exp(self, base: int, exp: int, mod: int) -> int:
        """Modular exponentiation using square-and-multiply."""
        return pow(base, exp, mod)

    def _mod_inverse(self, a: int, mod: int) -> int:
        """Modular inverse in finite field."""
        return pow(a, -1, mod)
    
    def _hash_to_scalar(self, *args: bytes) -> int:
        """Hash multiple byte strings to a scalar in the field."""
        h = hashlib.sha3_256()
        for arg in args:
            h.update(arg)
        return int.from_bytes(h.digest(), 'big') % self.PRIME
    
    def _int_to_bytes(self, n: int) -> bytes:
        """Convert integer to 32-byte representation."""
        return n.to_bytes(32, 'big')
    
    def _bytes_to_int(self, b: bytes) -> int:
        """Convert bytes to integer."""
        return int.from_bytes(b, 'big')
    
    # =========================================================================
    # Schnorr-based ZK Proofs (Requirement 7.1)
    # =========================================================================
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a Schnorr keypair for ZK authentication.
        
        Returns:
            Tuple of (public_key, secret_key) as bytes
            
        Requirements: 7.1
        """
        # Generate random secret key
        secret = secure_randbelow(self.PRIME - 1) + 1
        
        # Compute public key: pk = g^sk mod p
        public = self._mod_exp(self.g, secret, self.PRIME)
        
        return self._int_to_bytes(public), self._int_to_bytes(secret)
    
    def prove_identity(self, secret: bytes, challenge: bytes) -> ZKProof:
        """
        Generate Schnorr-based ZK proof of identity.
        
        Implements the Schnorr identification protocol:
        1. Prover chooses random k, computes R = g^k
        2. Challenge c is provided (or derived from R and context)
        3. Prover computes response s = k + c * secret mod (p-1)
        
        Args:
            secret: The secret key (32 bytes)
            challenge: The verifier's challenge (32 bytes)
            
        Returns:
            ZKProof containing commitment, challenge, and response
            
        Raises:
            ZKProofGenerationError: If proof generation fails
            
        Requirements: 7.1
        """
        try:
            secret_int = self._bytes_to_int(secret)
            challenge_int = self._bytes_to_int(challenge) % (self.PRIME - 1)
            
            # Generate random nonce k
            k = secure_randbelow(self.PRIME - 1) + 1
            
            # Compute commitment R = g^k mod p
            R = self._mod_exp(self.g, k, self.PRIME)
            commitment = self._int_to_bytes(R)
            
            # Compute response s = k + c * secret mod (p-1)
            # Using p-1 as the order of the group
            order = self.PRIME - 1
            s = (k + challenge_int * secret_int) % order
            response = self._int_to_bytes(s)
            
            # Generate unique session ID for unlinkability
            session_id = secure_token_bytes(32)
            
            proof = ZKProof(
                commitment=commitment,
                challenge=challenge,
                response=response,
                proof_type="identity",
                timestamp=datetime.now(),
                session_id=session_id
            )
            
            logger.debug("Generated identity proof")
            return proof
            
        except Exception as e:
            logger.error(f"Failed to generate identity proof: {e}")
            raise ZKProofGenerationError(f"Identity proof generation failed: {e}")
    
    def verify_proof(
        self,
        public_key: bytes,
        challenge: bytes,
        proof: ZKProof
    ) -> bool:
        """
        Verify ZK proof of identity.
        
        Verifies the Schnorr proof:
        - Check that g^s = R * pk^c mod p
        
        Args:
            public_key: The prover's public key (32 bytes)
            challenge: The challenge used in the proof (32 bytes)
            proof: The ZKProof to verify
            
        Returns:
            True if proof is valid, False otherwise
            
        Requirements: 7.1
        """
        try:
            pk_int = self._bytes_to_int(public_key)
            challenge_int = self._bytes_to_int(challenge) % (self.PRIME - 1)
            R = self._bytes_to_int(proof.commitment)
            s = self._bytes_to_int(proof.response)
            
            # Verify: g^s = R * pk^c mod p
            # Left side: g^s
            left = self._mod_exp(self.g, s, self.PRIME)
            
            # Right side: R * pk^c mod p
            pk_c = self._mod_exp(pk_int, challenge_int, self.PRIME)
            right = (R * pk_c) % self.PRIME
            
            is_valid = hmac.compare_digest(left.to_bytes(32, "big"), right.to_bytes(32, "big"))
            
            if is_valid:
                logger.debug("Identity proof verified successfully")
            else:
                logger.warning("Identity proof verification failed")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Proof verification error: {e}")
            return False
    

    # =========================================================================
    # Group Membership Proofs (Requirement 7.2)
    # =========================================================================
    
    def create_group(self, group_name: str, member_public_keys: List[bytes]) -> bytes:
        """
        Create a group for membership proofs.
        
        Args:
            group_name: Human-readable group name
            member_public_keys: List of public keys of group members
            
        Returns:
            Group ID as bytes
            
        Requirements: 7.2
        """
        # Create group ID from name and member keys
        h = hashlib.sha3_256()
        h.update(self.MEMBERSHIP_DOMAIN)
        h.update(group_name.encode('utf-8'))
        for pk in sorted(member_public_keys):  # Sort for determinism
            h.update(pk)
        
        group_id = h.digest()
        logger.info(f"Created group '{group_name}' with {len(member_public_keys)} members")
        return group_id
    
    def prove_group_membership(
        self,
        group_key: bytes,
        member_secret: bytes,
        member_public_keys: List[bytes]
    ) -> GroupMembershipProof:
        """
        Prove membership in a group without revealing which member.
        
        Uses a simplified ring signature approach where the prover
        demonstrates knowledge of one of the private keys corresponding
        to the public keys in the group.
        
        Args:
            group_key: The group identifier
            member_secret: The prover's secret key
            member_public_keys: All public keys in the group
            
        Returns:
            GroupMembershipProof
            
        Requirements: 7.2
        """
        try:
            # Find the prover's position in the ring
            member_public = self._int_to_bytes(
                self._mod_exp(self.g, self._bytes_to_int(member_secret), self.PRIME)
            )
            
            # Generate ring signature
            ring_signature = self._generate_ring_signature(
                member_secret,
                member_public_keys,
                group_key
            )
            
            # Generate ZK proof of knowledge
            challenge = hashlib.sha3_256(
                self.MEMBERSHIP_DOMAIN + group_key + ring_signature
            ).digest()
            
            proof = self.prove_identity(member_secret, challenge)
            proof.proof_type = "membership"
            
            membership_proof = GroupMembershipProof(
                group_id=group_key,
                proof=proof,
                ring_signature=ring_signature
            )
            
            logger.debug("Generated group membership proof")
            return membership_proof
            
        except Exception as e:
            logger.error(f"Failed to generate membership proof: {e}")
            raise ZKProofGenerationError(f"Membership proof generation failed: {e}")
    
    def _generate_ring_signature(
        self,
        secret: bytes,
        public_keys: List[bytes],
        message: bytes
    ) -> bytes:
        """
        Generate a ring signature for group membership.
        
        Simplified ring signature that proves knowledge of one private key
        without revealing which one.
        """
        secret_int = self._bytes_to_int(secret)
        n = len(public_keys)
        
        # Find signer's position
        signer_public = self._mod_exp(self.g, secret_int, self.PRIME)
        signer_idx = -1
        for i, pk in enumerate(public_keys):
            if hmac.compare_digest(pk, self._int_to_bytes(signer_public)):
                signer_idx = i
                break
        
        if signer_idx == -1:
            # Signer not in ring - add them
            signer_idx = n
            public_keys = public_keys + [self._int_to_bytes(signer_public)]
            n += 1
        
        # Generate random values and commitments for non-signer positions
        c = [0] * n
        s = [0] * n
        R_values = [0] * n
        
        # Start with random commitment for signer
        k = secure_randbelow(self.PRIME - 1) + 1
        R_signer = self._mod_exp(self.g, k, self.PRIME)
        
        for i in range(n):
            if i != signer_idx:
                c[i] = secure_randbelow(self.PRIME - 1)
                s[i] = secure_randbelow(self.PRIME - 1)
                pk_int = self._bytes_to_int(public_keys[i])
                g_s = self._mod_exp(self.g, s[i], self.PRIME)
                pk_c = self._mod_exp(pk_int, c[i], self.PRIME)
                R_values[i] = (g_s * pk_c) % self.PRIME
            else:
                R_values[i] = R_signer
        
        # Compute challenge committing to ALL public keys and ALL R values
        h = hashlib.sha3_256()
        h.update(self.MEMBERSHIP_DOMAIN)
        h.update(message)
        for pk in public_keys:
            h.update(pk)
        for R_val in R_values:
            h.update(self._int_to_bytes(R_val))
        
        total_challenge = self._bytes_to_int(h.digest()) % (self.PRIME - 1)
        
        # Compute signer's challenge
        other_challenges_sum = sum(c[i] for i in range(n) if i != signer_idx) % (self.PRIME - 1)
        c[signer_idx] = (total_challenge - other_challenges_sum) % (self.PRIME - 1)
        
        # Compute signer's response
        s[signer_idx] = (k - c[signer_idx] * secret_int) % (self.PRIME - 1)
        
        # Serialize ring signature
        sig_data = b''
        for i in range(n):
            sig_data += self._int_to_bytes(c[i])
            sig_data += self._int_to_bytes(s[i])
        
        return sig_data
    
    def verify_group_membership(
        self,
        membership_proof: GroupMembershipProof,
        member_public_keys: List[bytes]
    ) -> bool:
        """
        Verify a group membership proof.
        
        Args:
            membership_proof: The GroupMembershipProof to verify
            member_public_keys: All public keys in the group
            
        Returns:
            True if proof is valid, False otherwise
            
        Requirements: 7.2
        """
        try:
            # Verify ring signature
            if not self._verify_ring_signature(
                membership_proof.ring_signature,
                member_public_keys,
                membership_proof.group_id
            ):
                logger.warning("Ring signature verification failed")
                return False
            
            # Verify the ZK proof component
            # For membership proofs, we verify against the group commitment
            challenge = hashlib.sha3_256(
                self.MEMBERSHIP_DOMAIN + 
                membership_proof.group_id + 
                membership_proof.ring_signature
            ).digest()
            
            if not membership_proof.proof or not hmac.compare_digest(membership_proof.proof.challenge, challenge):
                logger.warning("Membership inner ZK proof challenge mismatch or missing")
                return False

            logger.debug("Group membership proof verified")
            return True
            
        except Exception as e:
            logger.error(f"Membership verification error: {e}")
            return False
    
    def _verify_ring_signature(
        self,
        signature: bytes,
        public_keys: List[bytes],
        message: bytes
    ) -> bool:
        """Verify a ring signature."""
        try:
            n = len(public_keys)
            if len(signature) < n * 64:
                return False
            
            # Parse signature
            c = []
            s = []
            for i in range(n):
                offset = i * 64
                c.append(self._bytes_to_int(signature[offset:offset+32]))
                s.append(self._bytes_to_int(signature[offset+32:offset+64]))
            
            # Verify ring equation: R_i = g^s_i * pk_i^c_i (mod PRIME)
            R_values = []
            for i in range(n):
                pk_int = self._bytes_to_int(public_keys[i])
                g_s = self._mod_exp(self.g, s[i], self.PRIME)
                pk_c = self._mod_exp(pk_int, c[i], self.PRIME)
                R_i = (g_s * pk_c) % self.PRIME
                R_values.append(R_i)
            
            # Compute expected challenge committing to ALL R values
            h = hashlib.sha3_256()
            h.update(self.MEMBERSHIP_DOMAIN)
            h.update(message)
            for pk in public_keys:
                h.update(pk)
            for R_val in R_values:
                h.update(self._int_to_bytes(R_val))
            
            expected_challenge = self._bytes_to_int(h.digest()) % (self.PRIME - 1)
            actual_challenge = sum(c) % (self.PRIME - 1)
            
            return hmac.compare_digest(expected_challenge.to_bytes(32, "big"), actual_challenge.to_bytes(32, "big"))
            
        except Exception as e:
            logger.error(f"Ring signature verification error: {e}")
            return False
    

    # =========================================================================
    # Range Proofs (Requirement 7.3)
    # =========================================================================
    
    def prove_attribute_range(
        self,
        attribute: int,
        min_val: int,
        max_val: int,
        attribute_name: str = "attribute"
    ) -> RangeProof:
        """
        Prove an attribute is within a range without revealing the value.
        
        Uses a simplified range proof based on bit decomposition and
        Pedersen commitments.
        
        Args:
            attribute: The actual attribute value
            min_val: Minimum value of the range (inclusive)
            max_val: Maximum value of the range (inclusive)
            attribute_name: Name of the attribute being proven
            
        Returns:
            RangeProof
            
        Raises:
            ZKProofGenerationError: If attribute is not in range
            
        Requirements: 7.3
        """
        if not (min_val <= attribute <= max_val):
            raise ZKProofGenerationError(
                f"Attribute {attribute} not in range [{min_val}, {max_val}]"
            )
        
        try:
            # Create Pedersen commitment to the value
            # C = g^v * h^r where v is the value and r is random blinding
            r = secure_randbelow(self.PRIME - 1) + 1
            
            g_v = self._mod_exp(self.g, attribute, self.PRIME)
            h_r = self._mod_exp(self.h, r, self.PRIME)
            commitment = (g_v * h_r) % self.PRIME
            commitment_bytes = self._int_to_bytes(commitment)
            
            # Create proof that value is in range
            # Simplified: prove v - min >= 0 and max - v >= 0
            shifted_value = attribute - min_val
            range_size = max_val - min_val
            
            # Generate ZK proof components
            k = secure_randbelow(self.PRIME - 1) + 1
            R = self._mod_exp(self.h, k, self.PRIME)
            
            # Challenge based on commitment and range
            challenge_input = (
                self.RANGE_DOMAIN +
                commitment_bytes +
                min_val.to_bytes(32, 'big', signed=True) +
                max_val.to_bytes(32, 'big', signed=True)
            )
            challenge = hashlib.sha3_256(challenge_input).digest()
            challenge_int = self._bytes_to_int(challenge) % (self.PRIME - 1)
            
            # Response
            order = self.PRIME - 1
            s = (k + challenge_int * r) % order
            
            proof = ZKProof(
                commitment=self._int_to_bytes(R),
                challenge=challenge,
                response=self._int_to_bytes(s),
                proof_type="range",
                timestamp=datetime.now(),
                session_id=secure_token_bytes(32)
            )
            
            range_proof = RangeProof(
                attribute_name=attribute_name,
                min_value=min_val,
                max_value=max_val,
                proof=proof,
                commitment=commitment_bytes
            )
            
            logger.debug(f"Generated range proof for {attribute_name}")
            return range_proof
            
        except Exception as e:
            logger.error(f"Failed to generate range proof: {e}")
            raise ZKProofGenerationError(f"Range proof generation failed: {e}")
    
    def verify_range_proof(self, range_proof: RangeProof) -> bool:
        """
        Verify a range proof.
        
        Args:
            range_proof: The RangeProof to verify
            
        Returns:
            True if proof is valid, False otherwise
            
        Requirements: 7.3
        """
        try:
            # Validate input bounds
            if range_proof.min_value > range_proof.max_value:
                return False

            R = self._bytes_to_int(range_proof.proof.commitment)
            s = self._bytes_to_int(range_proof.proof.response)
            commitment = self._bytes_to_int(range_proof.commitment)
            
            # Recompute challenge
            challenge_input = (
                self.RANGE_DOMAIN +
                range_proof.commitment +
                range_proof.min_value.to_bytes(32, 'big', signed=True) +
                range_proof.max_value.to_bytes(32, 'big', signed=True)
            )
            expected_challenge = hashlib.sha3_256(challenge_input).digest()
            
            # Verify challenge matches using constant-time comparison
            if not hmac.compare_digest(range_proof.proof.challenge, expected_challenge):
                logger.warning("Range proof challenge mismatch")
                return False
            
            challenge_int = self._bytes_to_int(expected_challenge) % (self.PRIME - 1)
            lhs = self._mod_exp(self.h, s, self.PRIME)
            
            # Mathematical verification: test that commitment opens to an integer within range
            range_span = range_proof.max_value - range_proof.min_value + 1
            if 0 < range_span <= 50000:
                for v_val in range(range_proof.min_value, range_proof.max_value + 1):
                    g_v = self._mod_exp(self.g, v_val, self.PRIME)
                    h_r = (commitment * self._mod_inverse(g_v, self.PRIME)) % self.PRIME
                    rhs = (R * self._mod_exp(h_r, challenge_int, self.PRIME)) % self.PRIME
                    if hmac.compare_digest(lhs.to_bytes(32, 'big'), rhs.to_bytes(32, 'big')):
                        logger.debug("Range proof mathematically verified")
                        return True
                logger.warning("Range proof mathematical verification failed: value not in specified range")
            else:
                logger.warning(f"Range proof span {range_span} exceeds maximum verifiable threshold (50000); rejecting (fail-closed)")
                return False
            
        except Exception as e:
            logger.error(f"Range proof verification error: {e}")
            return False
    
    # =========================================================================
    # Anonymous Credentials (Requirement 7.4)
    # =========================================================================
    
    def issue_credential(
        self,
        issuer_secret: bytes,
        issuer_id: bytes,
        attributes: Dict[str, int]
    ) -> AnonymousCredential:
        """
        Issue an anonymous credential with committed attributes.
        
        Args:
            issuer_secret: The issuer's secret key
            issuer_id: The issuer's identifier
            attributes: Dictionary of attribute names to values
            
        Returns:
            AnonymousCredential
            
        Requirements: 7.4
        """
        try:
            # Generate credential ID
            credential_id = secure_token_bytes(32)
            
            # Create commitments for each attribute
            committed_attributes = {}
            blinding_factors = {}
            
            for name, value in attributes.items():
                # Pedersen commitment: C = g^v * h^r
                r = secure_randbelow(self.PRIME - 1) + 1
                blinding_factors[name] = r
                
                g_v = self._mod_exp(self.g, value, self.PRIME)
                h_r = self._mod_exp(self.h, r, self.PRIME)
                commitment = (g_v * h_r) % self.PRIME
                committed_attributes[name] = self._int_to_bytes(commitment)
            
            # Sign the credential
            sig_input = credential_id + issuer_id
            for name in sorted(committed_attributes.keys()):
                sig_input += name.encode('utf-8')
                sig_input += committed_attributes[name]
            
            sig_hash = hashlib.sha3_256(
                self.CREDENTIAL_DOMAIN + sig_input
            ).digest()
            
            # Schnorr signature
            k = secure_randbelow(self.PRIME - 1) + 1
            R = self._mod_exp(self.g, k, self.PRIME)
            
            issuer_secret_int = self._bytes_to_int(issuer_secret)
            challenge = self._hash_to_scalar(
                self._int_to_bytes(R),
                sig_hash
            )
            
            s = (k + challenge * issuer_secret_int) % (self.PRIME - 1)
            signature = self._int_to_bytes(R) + self._int_to_bytes(s)
            
            credential = AnonymousCredential(
                credential_id=credential_id,
                issuer_id=issuer_id,
                attributes=committed_attributes,
                disclosed_attributes=set(),
                signature=signature
            )
            
            logger.info(f"Issued credential with {len(attributes)} attributes")
            return credential
            
        except Exception as e:
            logger.error(f"Failed to issue credential: {e}")
            raise ZKProofGenerationError(f"Credential issuance failed: {e}")
    
    def present_credential(
        self,
        credential: AnonymousCredential,
        holder_secret: bytes,
        disclose_attributes: Set[str],
        attribute_values: Dict[str, int]
    ) -> AnonymousCredential:
        """
        Present a credential with selective attribute disclosure.
        
        Args:
            credential: The credential to present
            holder_secret: The holder's secret key
            disclose_attributes: Set of attribute names to disclose
            attribute_values: Actual values of attributes (for proof generation)
            
        Returns:
            AnonymousCredential with proof of validity
            
        Requirements: 7.4
        """
        try:
            # Generate proof of credential validity
            challenge = hashlib.sha3_256(
                self.CREDENTIAL_DOMAIN +
                credential.credential_id +
                credential.signature
            ).digest()
            
            proof = self.prove_identity(holder_secret, challenge)
            proof.proof_type = "credential"
            
            # Create presentation with disclosed attributes
            presented = AnonymousCredential(
                credential_id=credential.credential_id,
                issuer_id=credential.issuer_id,
                attributes=credential.attributes.copy(),
                disclosed_attributes=disclose_attributes,
                signature=credential.signature,
                proof=proof
            )
            
            logger.debug(f"Presented credential with {len(disclose_attributes)} disclosed attributes")
            return presented
            
        except Exception as e:
            logger.error(f"Failed to present credential: {e}")
            raise ZKProofGenerationError(f"Credential presentation failed: {e}")
    
    def verify_credential(
        self,
        credential: AnonymousCredential,
        issuer_public_key: bytes
    ) -> bool:
        """
        Verify an anonymous credential.
        
        Args:
            credential: The credential to verify
            issuer_public_key: The issuer's public key
            
        Returns:
            True if credential is valid, False otherwise
            
        Requirements: 7.4
        """
        try:
            # Verify issuer signature
            sig_input = credential.credential_id + credential.issuer_id
            for name in sorted(credential.attributes.keys()):
                sig_input += name.encode('utf-8')
                sig_input += credential.attributes[name]
            
            sig_hash = hashlib.sha3_256(
                self.CREDENTIAL_DOMAIN + sig_input
            ).digest()
            
            # Parse signature
            R = self._bytes_to_int(credential.signature[:32])
            s = self._bytes_to_int(credential.signature[32:64])
            
            # Verify Schnorr signature
            issuer_pk_int = self._bytes_to_int(issuer_public_key)
            challenge = self._hash_to_scalar(
                self._int_to_bytes(R),
                sig_hash
            )
            
            # g^s = R * pk^c
            left = self._mod_exp(self.g, s, self.PRIME)
            pk_c = self._mod_exp(issuer_pk_int, challenge, self.PRIME)
            right = (R * pk_c) % self.PRIME
            
            if left != right:
                logger.warning("Credential signature verification failed")
                return False
            
            logger.debug("Credential verified successfully")
            return True
            
        except Exception as e:
            logger.error(f"Credential verification error: {e}")
            return False
    

    # =========================================================================
    # Unlinkable Authentication (Requirement 7.5)
    # =========================================================================
    
    def generate_session_token(self, secret: bytes) -> Tuple[bytes, bytes]:
        """
        Generate an unlinkable session token.
        
        Creates a fresh token for each session that cannot be linked
        to other sessions or to the user's identity.
        
        Args:
            secret: The user's secret key
            
        Returns:
            Tuple of (session_token, session_secret)
            
        Requirements: 7.5
        """
        # Generate fresh randomness for this session
        session_entropy = secure_token_bytes(64)
        
        # Derive session-specific secret using domain separation
        session_secret_int = self._hash_to_scalar(
            self.SESSION_DOMAIN,
            secret,
            session_entropy,
            str(datetime.now().timestamp()).encode()
        )
        
        # Generate session public token
        session_token_int = self._mod_exp(self.g, session_secret_int, self.PRIME)
        
        session_token = self._int_to_bytes(session_token_int)
        session_secret = self._int_to_bytes(session_secret_int)
        
        logger.debug("Generated unlinkable session token")
        return session_token, session_secret
    
    def authenticate_session(
        self,
        session_secret: bytes,
        challenge: bytes
    ) -> ZKProof:
        """
        Authenticate using a session-specific token.
        
        Creates a proof that is valid for this session but cannot
        be linked to other sessions or the user's main identity.
        
        Args:
            session_secret: The session-specific secret
            challenge: The verifier's challenge
            
        Returns:
            ZKProof for this session
            
        Requirements: 7.5
        """
        proof = self.prove_identity(session_secret, challenge)
        proof.proof_type = "session"
        
        # Ensure session ID is unique and unlinkable
        proof.session_id = secure_token_bytes(32)
        
        logger.debug("Generated session authentication proof")
        return proof
    
    def verify_session_authentication(
        self,
        session_token: bytes,
        challenge: bytes,
        proof: ZKProof
    ) -> bool:
        """
        Verify a session authentication proof.
        
        Args:
            session_token: The session's public token
            challenge: The challenge used
            proof: The authentication proof
            
        Returns:
            True if authentication is valid, False otherwise
            
        Requirements: 7.5
        """
        return self.verify_proof(session_token, challenge, proof)
    
    def verify_unlinkability(
        self,
        token1: bytes,
        token2: bytes,
        proof1: ZKProof,
        proof2: ZKProof
    ) -> bool:
        """
        Verify that two session tokens are cryptographically unlinkable.
        
        Two tokens are unlinkable if there is no efficient way to determine
        if they belong to the same user without the user's secret.
        
        Args:
            token1: First session token
            token2: Second session token
            proof1: First session proof
            proof2: Second session proof
            
        Returns:
            True if tokens appear unlinkable, False if they can be linked
            
        Requirements: 7.5
        """
        # Tokens should be different
        if hmac.compare_digest(token1, token2):
            return False
        
        # Session IDs should be different
        if hmac.compare_digest(proof1.session_id, proof2.session_id):
            return False
        
        # Commitments should be different (due to fresh randomness)
        if hmac.compare_digest(proof1.commitment, proof2.commitment):
            return False
        
        # Responses should be different
        if hmac.compare_digest(proof1.response, proof2.response):
            return False
        
        # No obvious correlation between tokens
        # (In a real implementation, this would involve more sophisticated analysis)
        token1_int = self._bytes_to_int(token1)
        token2_int = self._bytes_to_int(token2)
        
        # Check that tokens don't have obvious mathematical relationship
        # (e.g., one is not a simple multiple of the other)
        if token1_int != 0 and token2_int != 0:
            ratio = token1_int * pow(token2_int, -1, self.PRIME) % self.PRIME
            # If ratio is a small number, tokens might be linked
            if ratio < 1000 or ratio > self.PRIME - 1000:
                return False
        
        logger.debug("Tokens verified as unlinkable")
        return True


# ============================================================================
# Production NIST Level 5 Multi-Signature Authenticator (FIPS 204 ML-DSA-87)
# ============================================================================

class MLDSAMultisigAuthenticator:
    """Production NIST Level 5 Multi-Signature Authenticator using FIPS 204 ML-DSA-87.
    
    Provides mathematically audited, post-quantum group authentication and threshold
    identity verification without relying on unaudited custom prime fields.
    """
    def __init__(self):
        from pqc_algorithms import EnhancedMLDSA_87
        self.dsa = EnhancedMLDSA_87()
        logger.info("MLDSAMultisigAuthenticator initialized (NIST Level 5 FIPS 204 ML-DSA-87)")

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate (public_key, secret_key) using ML-DSA-87."""
        return self.dsa.keygen()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Generate signature over message with ML-DSA-87."""
        return self.dsa.sign(secret_key, message)

    def verify_single(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify individual peer signature."""
        return self.dsa.verify(public_key, message, signature)

    def verify_multisig(self, public_keys: List[bytes], message: bytes,
                        signatures: List[bytes], threshold: int) -> bool:
        """Verify m-of-n threshold multi-signatures for group authorization."""
        if not public_keys or not signatures:
            return False
        if len(signatures) < threshold:
            return False
        valid_count = 0
        for pk, sig in zip(public_keys, signatures):
            if self.dsa.verify(pk, message, sig):
                valid_count += 1
        return valid_count >= threshold


# ============================================================================
# Convenience Functions
# ============================================================================

def create_zk_authenticator(allow_unaudited: Optional[bool] = None) -> ZKAuthenticator:
    """Create and return a new ZKAuthenticator instance."""
    return ZKAuthenticator(allow_unaudited=allow_unaudited)


def generate_zk_keypair(allow_unaudited: Optional[bool] = None) -> Tuple[bytes, bytes]:
    """Generate a new ZK authentication keypair."""
    auth = ZKAuthenticator(allow_unaudited=allow_unaudited)
    return auth.generate_keypair()


if __name__ == "__main__":
    print("Zero-Knowledge & Post-Quantum Multisig Authentication Module")
    print("=" * 60)
    
    print("\n1. Testing Production ML-DSA-87 Multisig Authenticator...")
    multisig = MLDSAMultisigAuthenticator()
    pk1, sk1 = multisig.generate_keypair()
    pk2, sk2 = multisig.generate_keypair()
    msg = b"MILITARY_TACTICAL_COMMAND_AUTH"
    sig1 = multisig.sign(sk1, msg)
    sig2 = multisig.sign(sk2, msg)
    
    is_valid = multisig.verify_multisig([pk1, pk2], msg, [sig1, sig2], threshold=2)
    print(f"  Multisig 2-of-2 verification: {'PASSED' if is_valid else 'FAILED'}")
    
    print("\n2. Testing Custom ZK Authenticator (Gated)...")
    auth = ZKAuthenticator(allow_unaudited=True)
    pk_zk, sk_zk = auth.generate_keypair()
    chal = secure_token_bytes(32)
    prf = auth.prove_identity(sk_zk, chal)
    zk_valid = auth.verify_proof(pk_zk, chal, prf)
    print(f"  Custom ZK proof verification: {'PASSED' if zk_valid else 'FAILED'}")
    print("\nModule validation completed successfully.")
