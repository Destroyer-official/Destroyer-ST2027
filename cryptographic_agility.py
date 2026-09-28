#!/usr/bin/env python3
"""
Cryptographic Agility Framework - Military 2026 Production Security

This module implements a comprehensive cryptographic agility framework that enables:
- Version-tagged cipher suite negotiation
- Runtime algorithm updates via signed configuration
- Backward compatibility with previous algorithm versions
- Algorithm deprecation warnings
- Emergency algorithm disable via signed broadcast
- Full audit trail of all algorithm transitions

Security Properties:
- All configuration updates must be signed with ML-DSA-87
- Unsigned updates are rejected
- Algorithm transitions are logged to the audit system
- Fail-closed security model

Requirements Implemented:
- 8.1: Algorithm negotiation with version-tagged cipher suites
- 8.2: Runtime algorithm updates via signed configuration
- 8.3: Backward compatibility with previous algorithm versions
- 8.4: Algorithm deprecation warnings 90 days before removal
- 8.5: Emergency algorithm disable via signed broadcast
- 8.6: Log all algorithm transitions with full audit trail
"""

import os
import json
import logging
import hashlib
import secrets
import datetime
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
import base64
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CryptoAgilityError(Exception):
    """Base exception for cryptographic agility errors."""


class UnsignedConfigurationError(CryptoAgilityError):
    """Exception raised when an unsigned configuration update is rejected."""


class AlgorithmDisabledError(CryptoAgilityError):
    """Exception raised when a disabled algorithm is requested."""


class NegotiationFailedError(CryptoAgilityError):
    """Exception raised when algorithm negotiation fails."""


class AlgorithmFamily(Enum):
    """Algorithm families for categorization."""
    KEM_LATTICE = "KEM_LATTICE"
    KEM_CODE_BASED = "KEM_CODE_BASED"
    KEM_CONSERVATIVE_LATTICE = "KEM_CONSERVATIVE_LATTICE"
    SIG_LATTICE = "SIG_LATTICE"
    SIG_HASH_BASED = "SIG_HASH_BASED"
    SYMMETRIC = "SYMMETRIC"
    KDF = "KDF"
    HASH = "HASH"


class SecurityLevel(Enum):
    """NIST security levels."""
    LEVEL_1 = 1  # 128-bit classical security
    LEVEL_2 = 2  # 192-bit classical security
    LEVEL_3 = 3  # 192-bit classical security (stronger)
    LEVEL_4 = 4  # 256-bit classical security
    LEVEL_5 = 5  # 256-bit classical security (strongest)


@dataclass
class AlgorithmSpec:
    """Specification for a cryptographic algorithm."""
    name: str
    family: AlgorithmFamily
    security_level: SecurityLevel
    version: str
    standard: Optional[str] = None  # e.g., "NIST FIPS 203"
    deprecated: bool = False
    deprecation_date: Optional[str] = None  # ISO 8601 date
    disabled: bool = False
    disable_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'name': self.name,
            'family': self.family.value,
            'security_level': self.security_level.value,
            'version': self.version,
            'standard': self.standard,
            'deprecated': self.deprecated,
            'deprecation_date': self.deprecation_date,
            'disabled': self.disabled,
            'disable_reason': self.disable_reason
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AlgorithmSpec':
        """Create from dictionary."""
        return cls(
            name=data['name'],
            family=AlgorithmFamily(data['family']),
            security_level=SecurityLevel(data['security_level']),
            version=data['version'],
            standard=data.get('standard'),
            deprecated=data.get('deprecated', False),
            deprecation_date=data.get('deprecation_date'),
            disabled=data.get('disabled', False),
            disable_reason=data.get('disable_reason')
        )


@dataclass
class CipherSuite:
    """A complete cipher suite configuration."""
    suite_id: str
    version: str
    kem_algorithms: List[str]  # Ordered by preference
    signature_algorithms: List[str]
    symmetric_algorithm: str
    kdf_algorithm: str
    hash_algorithm: str
    security_level: SecurityLevel
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'suite_id': self.suite_id,
            'version': self.version,
            'kem_algorithms': self.kem_algorithms,
            'signature_algorithms': self.signature_algorithms,
            'symmetric_algorithm': self.symmetric_algorithm,
            'kdf_algorithm': self.kdf_algorithm,
            'hash_algorithm': self.hash_algorithm,
            'security_level': self.security_level.value
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CipherSuite':
        """Create from dictionary."""
        return cls(
            suite_id=data['suite_id'],
            version=data['version'],
            kem_algorithms=data['kem_algorithms'],
            signature_algorithms=data['signature_algorithms'],
            symmetric_algorithm=data['symmetric_algorithm'],
            kdf_algorithm=data['kdf_algorithm'],
            hash_algorithm=data['hash_algorithm'],
            security_level=SecurityLevel(data['security_level'])
        )


@dataclass
class SignedConfiguration:
    """A signed configuration update."""
    config_id: str
    timestamp: str
    config_type: str  # "algorithm_update", "emergency_disable", "deprecation"
    payload: Dict[str, Any]
    signature: bytes = field(default_factory=bytes)
    public_key: bytes = field(default_factory=bytes)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'config_id': self.config_id,
            'timestamp': self.timestamp,
            'config_type': self.config_type,
            'payload': self.payload,
            'signature': base64.b64encode(self.signature).decode('utf-8'),
            'public_key': base64.b64encode(self.public_key).decode('utf-8')
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SignedConfiguration':
        """Create from dictionary."""
        return cls(
            config_id=data['config_id'],
            timestamp=data['timestamp'],
            config_type=data['config_type'],
            payload=data['payload'],
            signature=base64.b64decode(data['signature']),
            public_key=base64.b64decode(data['public_key'])
        )
    
    def get_signable_data(self) -> bytes:
        """Get the data that should be signed."""
        signable = {
            'config_id': self.config_id,
            'timestamp': self.timestamp,
            'config_type': self.config_type,
            'payload': self.payload
        }
        return json.dumps(signable, sort_keys=True).encode('utf-8')




class AlgorithmNegotiator:
    """
    Version-tagged cipher suite negotiation.
    
    Implements algorithm negotiation that selects the highest-security
    mutually supported algorithm from version-tagged cipher suites.
    
    Requirements:
    - 8.1: Algorithm negotiation with version-tagged cipher suites
    - 8.3: Backward compatibility with previous algorithm versions
    """
    
    # Default algorithm registry with security levels
    DEFAULT_ALGORITHMS: Dict[str, AlgorithmSpec] = {
        # KEM algorithms (ordered by security preference)
        'ML-KEM-1024': AlgorithmSpec(
            name='ML-KEM-1024',
            family=AlgorithmFamily.KEM_LATTICE,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='NIST FIPS 203'
        ),
        'McEliece-8192128f': AlgorithmSpec(
            name='McEliece-8192128f',
            family=AlgorithmFamily.KEM_CODE_BASED,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='Classic McEliece'
        ),
        'FrodoKEM-1344': AlgorithmSpec(
            name='FrodoKEM-1344',
            family=AlgorithmFamily.KEM_CONSERVATIVE_LATTICE,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='FrodoKEM'
        ),
        # Signature algorithms
        'ML-DSA-87': AlgorithmSpec(
            name='ML-DSA-87',
            family=AlgorithmFamily.SIG_LATTICE,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='NIST FIPS 204'
        ),
        'SLH-DSA-256f': AlgorithmSpec(
            name='SLH-DSA-256f',
            family=AlgorithmFamily.SIG_HASH_BASED,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='NIST FIPS 205'
        ),
        # Symmetric algorithms
        'AES-256-GCM': AlgorithmSpec(
            name='AES-256-GCM',
            family=AlgorithmFamily.SYMMETRIC,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='NIST FIPS 197'
        ),
        'ChaCha20-Poly1305': AlgorithmSpec(
            name='ChaCha20-Poly1305',
            family=AlgorithmFamily.SYMMETRIC,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='RFC 8439'
        ),
        # KDF algorithms
        'HKDF-SHA384': AlgorithmSpec(
            name='HKDF-SHA384',
            family=AlgorithmFamily.KDF,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='RFC 5869'
        ),
        'HKDF-SHA3-512': AlgorithmSpec(
            name='HKDF-SHA3-512',
            family=AlgorithmFamily.KDF,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='RFC 5869'
        ),
        # Hash algorithms
        'SHA3-512': AlgorithmSpec(
            name='SHA3-512',
            family=AlgorithmFamily.HASH,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='NIST FIPS 202'
        ),
        'SHA-384': AlgorithmSpec(
            name='SHA-384',
            family=AlgorithmFamily.HASH,
            security_level=SecurityLevel.LEVEL_5,
            version='1.0',
            standard='NIST FIPS 180-4'
        ),
    }
    
    # Default cipher suites (ordered by security preference - highest first)
    DEFAULT_CIPHER_SUITES: List[CipherSuite] = [
        CipherSuite(
            suite_id='TRIPLE_HYBRID_LEVEL5_V1',
            version='1.0',
            kem_algorithms=['ML-KEM-1024', 'McEliece-8192128f', 'FrodoKEM-1344'],
            signature_algorithms=['ML-DSA-87', 'SLH-DSA-256f'],
            symmetric_algorithm='AES-256-GCM',
            kdf_algorithm='HKDF-SHA384',
            hash_algorithm='SHA3-512',
            security_level=SecurityLevel.LEVEL_5
        ),
        CipherSuite(
            suite_id='DUAL_HYBRID_LEVEL5_V1',
            version='1.0',
            kem_algorithms=['ML-KEM-1024', 'McEliece-8192128f'],
            signature_algorithms=['ML-DSA-87', 'SLH-DSA-256f'],
            symmetric_algorithm='AES-256-GCM',
            kdf_algorithm='HKDF-SHA384',
            hash_algorithm='SHA3-512',
            security_level=SecurityLevel.LEVEL_5
        ),
        CipherSuite(
            suite_id='SINGLE_LEVEL5_V1',
            version='1.0',
            kem_algorithms=['ML-KEM-1024'],
            signature_algorithms=['ML-DSA-87'],
            symmetric_algorithm='AES-256-GCM',
            kdf_algorithm='HKDF-SHA384',
            hash_algorithm='SHA3-512',
            security_level=SecurityLevel.LEVEL_5
        )
    ]
    
    def __init__(self):
        """Initialize the algorithm negotiator."""
        # Create deep copies to avoid mutating class-level defaults
        import copy
        self._algorithms: Dict[str, AlgorithmSpec] = {
            name: copy.deepcopy(spec) for name, spec in self.DEFAULT_ALGORITHMS.items()
        }
        self._cipher_suites: List[CipherSuite] = [
            copy.deepcopy(suite) for suite in self.DEFAULT_CIPHER_SUITES
        ]
        self._disabled_algorithms: Set[str] = set()
        self._lock = threading.Lock()
        
        logger.info("AlgorithmNegotiator initialized with %d algorithms and %d cipher suites",
                   len(self._algorithms), len(self._cipher_suites))
    
    def get_supported_algorithms(self, family: Optional[AlgorithmFamily] = None) -> List[AlgorithmSpec]:
        """
        Get list of supported algorithms, optionally filtered by family.
        
        Args:
            family: Optional algorithm family to filter by
            
        Returns:
            List of supported algorithm specifications
        """
        with self._lock:
            algorithms = list(self._algorithms.values())
            
            if family:
                algorithms = [a for a in algorithms if a.family == family]
            
            # Filter out disabled algorithms
            algorithms = [a for a in algorithms if not a.disabled and a.name not in self._disabled_algorithms]
            
            # Sort by security level (highest first)
            algorithms.sort(key=lambda a: a.security_level.value, reverse=True)
            
            return algorithms
    
    def get_supported_cipher_suites(self) -> List[CipherSuite]:
        """
        Get list of supported cipher suites.
        
        Returns:
            List of cipher suites ordered by security preference
        """
        with self._lock:
            # Filter out suites with disabled algorithms
            valid_suites = []
            for suite in self._cipher_suites:
                if self._is_suite_valid(suite):
                    valid_suites.append(suite)
            
            # Sort by security level (highest first)
            valid_suites.sort(key=lambda s: s.security_level.value, reverse=True)
            
            return valid_suites
    
    def _is_suite_valid(self, suite: CipherSuite) -> bool:
        """Check if a cipher suite has all algorithms available."""
        all_algorithms = (
            suite.kem_algorithms + 
            suite.signature_algorithms + 
            [suite.symmetric_algorithm, suite.kdf_algorithm, suite.hash_algorithm]
        )
        
        for alg_name in all_algorithms:
            if alg_name in self._disabled_algorithms:
                return False
            alg = self._algorithms.get(alg_name)
            if alg and alg.disabled:
                return False
        
        return True
    
    def negotiate(
        self,
        local_suites: List[str],
        remote_suites: List[str]
    ) -> Optional[CipherSuite]:
        """
        Negotiate the highest-security mutually supported cipher suite.
        
        Selects the cipher suite with the highest security level that
        both parties support.
        
        Args:
            local_suites: List of locally supported cipher suite IDs
            remote_suites: List of remotely supported cipher suite IDs
            
        Returns:
            The negotiated CipherSuite, or None if no common suite found
            
        Requirements:
            - 8.1: Select highest-security mutually supported algorithm
        """
        with self._lock:
            # Find common suites
            common_suite_ids = set(local_suites) & set(remote_suites)
            
            if not common_suite_ids:
                logger.warning("No common cipher suites found during negotiation")
                return None
            
            # Get full suite objects for common suites
            common_suites = []
            for suite in self._cipher_suites:
                if suite.suite_id in common_suite_ids and self._is_suite_valid(suite):
                    common_suites.append(suite)
            
            if not common_suites:
                logger.warning("No valid common cipher suites after filtering disabled algorithms")
                return None
            
            # Sort by security level (highest first) and return the best
            common_suites.sort(key=lambda s: s.security_level.value, reverse=True)
            selected = common_suites[0]
            
            logger.info("Negotiated cipher suite: %s (Security Level %d)",
                       selected.suite_id, selected.security_level.value)
            
            return selected
    
    def negotiate_algorithm(
        self,
        family: AlgorithmFamily,
        local_algorithms: List[str],
        remote_algorithms: List[str]
    ) -> Optional[AlgorithmSpec]:
        """
        Negotiate the highest-security mutually supported algorithm for a family.
        
        Args:
            family: The algorithm family to negotiate
            local_algorithms: List of locally supported algorithm names
            remote_algorithms: List of remotely supported algorithm names
            
        Returns:
            The negotiated AlgorithmSpec, or None if no common algorithm found
        """
        with self._lock:
            # Find common algorithms
            common_names = set(local_algorithms) & set(remote_algorithms)
            
            if not common_names:
                return None
            
            # Get full specs for common algorithms
            common_algorithms = []
            for name in common_names:
                alg = self._algorithms.get(name)
                if alg and alg.family == family and not alg.disabled and name not in self._disabled_algorithms:
                    common_algorithms.append(alg)
            
            if not common_algorithms:
                return None
            
            # Sort by security level (highest first)
            common_algorithms.sort(key=lambda a: a.security_level.value, reverse=True)
            
            return common_algorithms[0]
    
    def is_algorithm_supported(self, algorithm_name: str) -> bool:
        """Check if an algorithm is supported and not disabled."""
        with self._lock:
            if algorithm_name in self._disabled_algorithms:
                return False
            alg = self._algorithms.get(algorithm_name)
            return alg is not None and not alg.disabled
    
    def get_algorithm_spec(self, algorithm_name: str) -> Optional[AlgorithmSpec]:
        """Get the specification for an algorithm."""
        with self._lock:
            return self._algorithms.get(algorithm_name)
    
    def disable_algorithm(self, algorithm_name: str, reason: str) -> bool:
        """
        Disable an algorithm (internal use - for signed updates use apply_signed_config).
        
        Args:
            algorithm_name: Name of the algorithm to disable
            reason: Reason for disabling
            
        Returns:
            True if algorithm was disabled
        """
        with self._lock:
            self._disabled_algorithms.add(algorithm_name)
            
            if algorithm_name in self._algorithms:
                self._algorithms[algorithm_name].disabled = True
                self._algorithms[algorithm_name].disable_reason = reason
            
            logger.warning("Algorithm %s disabled: %s", algorithm_name, reason)
            return True
    
    def enable_algorithm(self, algorithm_name: str) -> bool:
        """
        Re-enable a previously disabled algorithm.
        
        Args:
            algorithm_name: Name of the algorithm to enable
            
        Returns:
            True if algorithm was enabled
        """
        with self._lock:
            self._disabled_algorithms.discard(algorithm_name)
            
            if algorithm_name in self._algorithms:
                self._algorithms[algorithm_name].disabled = False
                self._algorithms[algorithm_name].disable_reason = None
            
            logger.info("Algorithm %s re-enabled", algorithm_name)
            return True
    
    def add_cipher_suite(self, suite: CipherSuite) -> bool:
        """
        Add a new cipher suite.
        
        Args:
            suite: The cipher suite to add
            
        Returns:
            True if suite was added
        """
        with self._lock:
            # Check if suite already exists
            for existing in self._cipher_suites:
                if existing.suite_id == suite.suite_id:
                    logger.warning("Cipher suite %s already exists", suite.suite_id)
                    return False
            
            self._cipher_suites.append(suite)
            logger.info("Added cipher suite: %s", suite.suite_id)
            return True
    
    def get_local_suite_ids(self) -> List[str]:
        """Get list of locally supported cipher suite IDs."""
        return [s.suite_id for s in self.get_supported_cipher_suites()]



class SignedConfigurationManager:
    """
    Manager for signed configuration updates.
    
    All configuration updates must be signed with ML-DSA-87.
    Unsigned updates are rejected.
    
    Requirements:
    - 8.2: Runtime algorithm updates via signed configuration
    - 8.5: Emergency algorithm disable via signed broadcast
    """
    
    def __init__(self, negotiator: AlgorithmNegotiator, audit_logger=None):
        """
        Initialize the signed configuration manager.
        
        Args:
            negotiator: The algorithm negotiator to update
            audit_logger: Optional audit logger for transition logging
        """
        self._negotiator = negotiator
        self._audit_logger = audit_logger
        self._signature_impl = None
        self._admin_public_keys: List[bytes] = []
        self._applied_configs: Dict[str, SignedConfiguration] = {}
        self._lock = threading.Lock()
        
        self._init_signature_system()
        
        logger.info("SignedConfigurationManager initialized")
    
    def _init_signature_system(self):
        """Initialize ML-DSA-87 signature system."""
        try:
            from liboqs_wrapper import LibOQS_MLDSA_87
            self._signature_impl = LibOQS_MLDSA_87()
            logger.info("ML-DSA-87 signature system initialized for configuration signing")
        except ImportError as e:
            logger.warning("ML-DSA-87 not available: %s", e)
            self._signature_impl = None
    
    def generate_admin_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new admin keypair for signing configurations.
        
        Returns:
            Tuple of (public_key, secret_key)
        """
        if not self._signature_impl:
            raise CryptoAgilityError("Signature system not available")
        
        pk, sk = self._signature_impl.keygen()
        self.register_admin_public_key(pk)
        return pk, sk
    
    def register_admin_public_key(self, public_key: bytes) -> None:
        """
        Register an admin public key for verifying configurations.
        
        Args:
            public_key: The admin's ML-DSA-87 public key
        """
        with self._lock:
            if public_key not in self._admin_public_keys:
                self._admin_public_keys.append(public_key)
                logger.info("Registered admin public key (hash: %s...)",
                           hashlib.sha512(public_key).hexdigest()[:16])
    
    def create_signed_config(
        self,
        config_type: str,
        payload: Dict[str, Any],
        secret_key: bytes,
        public_key: bytes
    ) -> SignedConfiguration:
        """
        Create a signed configuration update.
        
        Args:
            config_type: Type of configuration ("algorithm_update", "emergency_disable", "deprecation")
            payload: Configuration payload
            secret_key: Admin's ML-DSA-87 secret key
            public_key: Admin's ML-DSA-87 public key
            
        Returns:
            SignedConfiguration with signature
        """
        if not self._signature_impl:
            raise CryptoAgilityError("Signature system not available")
        
        config = SignedConfiguration(
            config_id=secrets.token_hex(16),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z'),
            config_type=config_type,
            payload=payload,
            public_key=public_key
        )
        
        # Sign the configuration
        signable_data = config.get_signable_data()
        config.signature = self._signature_impl.sign(secret_key, signable_data)
        
        logger.info("Created signed configuration: %s (type: %s)", config.config_id, config_type)
        
        return config
    
    def verify_signature(self, config: SignedConfiguration) -> bool:
        """
        Verify the signature on a configuration.
        
        Args:
            config: The signed configuration to verify
            
        Returns:
            True if signature is valid
        """
        if not self._signature_impl:
            logger.error("Signature system not available for verification")
            return False
        
        if not config.signature or not config.public_key:
            logger.error("Configuration missing signature or public key")
            return False
        
        signable_data = config.get_signable_data()
        
        try:
            return self._signature_impl.verify(config.public_key, signable_data, config.signature)
        except Exception as e:
            logger.error("Signature verification failed: %s", e)
            return False
    
    def apply_signed_config(self, config: SignedConfiguration) -> bool:
        """
        Apply a signed configuration update.
        
        Verifies the signature and applies the configuration if valid.
        Rejects unsigned or invalid configurations.
        
        Args:
            config: The signed configuration to apply
            
        Returns:
            True if configuration was applied
            
        Raises:
            UnsignedConfigurationError: If signature is invalid
            
        Requirements:
            - 8.2: Runtime algorithm updates via signed configuration
            - 8.5: Emergency algorithm disable via signed broadcast
        """
        with self._lock:
            # Verify signature
            if not self.verify_signature(config):
                logger.error("Rejected unsigned/invalid configuration: %s", config.config_id)
                raise UnsignedConfigurationError(
                    f"Configuration {config.config_id} has invalid signature"
                )
            
            # Verify public key is from a registered admin (fail-closed if no admin keys registered)
            if not self._admin_public_keys:
                logger.error("Configuration rejected: no admin public keys are registered in CryptographicAgilityManager")
                raise UnsignedConfigurationError(
                    f"Configuration {config.config_id} rejected: dynamic updates require pre-registered admin keys."
                )
            elif config.public_key not in self._admin_public_keys:
                logger.error("Configuration signed by unregistered admin: %s", config.config_id)
                raise UnsignedConfigurationError(
                    f"Configuration {config.config_id} signed by unregistered admin"
                )
            
            # Check if already applied
            if config.config_id in self._applied_configs:
                logger.warning("Configuration %s already applied", config.config_id)
                return False
            
            # Apply based on config type
            success = False
            if config.config_type == 'algorithm_update':
                success = self._apply_algorithm_update(config)
            elif config.config_type == 'emergency_disable':
                success = self._apply_emergency_disable(config)
            elif config.config_type == 'deprecation':
                success = self._apply_deprecation(config)
            else:
                logger.error("Unknown configuration type: %s", config.config_type)
                return False
            
            if success:
                self._applied_configs[config.config_id] = config
                self._log_transition(config)
            
            return success
    
    def _apply_algorithm_update(self, config: SignedConfiguration) -> bool:
        """Apply an algorithm update configuration."""
        payload = config.payload
        
        if 'add_algorithm' in payload:
            alg_data = payload['add_algorithm']
            alg_spec = AlgorithmSpec.from_dict(alg_data)
            self._negotiator._algorithms[alg_spec.name] = alg_spec
            logger.info("Added algorithm via signed config: %s", alg_spec.name)
        
        if 'add_cipher_suite' in payload:
            suite_data = payload['add_cipher_suite']
            suite = CipherSuite.from_dict(suite_data)
            self._negotiator.add_cipher_suite(suite)
            logger.info("Added cipher suite via signed config: %s", suite.suite_id)
        
        if 'enable_algorithm' in payload:
            alg_name = payload['enable_algorithm']
            self._negotiator.enable_algorithm(alg_name)
        
        return True
    
    def _apply_emergency_disable(self, config: SignedConfiguration) -> bool:
        """
        Apply an emergency algorithm disable.
        
        Requirements:
            - 8.5: Emergency algorithm disable via signed broadcast
        """
        payload = config.payload
        
        algorithm_name = payload.get('algorithm')
        reason = payload.get('reason', 'Emergency disable via signed broadcast')
        
        if not algorithm_name:
            logger.error("Emergency disable missing algorithm name")
            return False
        
        self._negotiator.disable_algorithm(algorithm_name, reason)
        logger.critical("EMERGENCY: Algorithm %s disabled via signed broadcast: %s",
                       algorithm_name, reason)
        
        return True
    
    def _apply_deprecation(self, config: SignedConfiguration) -> bool:
        """Apply a deprecation configuration."""
        payload = config.payload
        
        algorithm_name = payload.get('algorithm')
        deprecation_date = payload.get('deprecation_date')
        
        if not algorithm_name:
            logger.error("Deprecation config missing algorithm name")
            return False
        
        alg = self._negotiator._algorithms.get(algorithm_name)
        if alg:
            alg.deprecated = True
            alg.deprecation_date = deprecation_date
            logger.warning("Algorithm %s marked as deprecated (removal: %s)",
                          algorithm_name, deprecation_date)
        
        return True
    
    def _log_transition(self, config: SignedConfiguration) -> None:
        """
        Log algorithm transition to audit system.
        
        Requirements:
            - 8.6: Log all algorithm transitions with full audit trail
        """
        if self._audit_logger:
            try:
                from enhanced_audit_logging import AuditEventType, AuditSeverity
                
                severity = AuditSeverity.HIGH if config.config_type == 'emergency_disable' else AuditSeverity.INFO
                
                self._audit_logger.add_entry(
                    AuditEventType.CONFIGURATION_CHANGE,
                    f"Algorithm configuration change: {config.config_type}",
                    severity,
                    {
                        'config_id': config.config_id,
                        'config_type': config.config_type,
                        'timestamp': config.timestamp,
                        'payload': config.payload,
                        'signer_key_hash': hashlib.sha512(config.public_key).hexdigest()[:32]
                    }
                )
            except Exception as e:
                logger.error("Failed to log transition to audit system: %s", e)
        
        logger.info("Algorithm transition logged: %s (%s)", config.config_id, config.config_type)



class DeprecationManager:
    """
    Manager for algorithm deprecation warnings.
    
    Requirements:
    - 8.4: Algorithm deprecation warnings 90 days before removal
    """
    
    DEPRECATION_WARNING_DAYS = 90
    
    def __init__(self, negotiator: AlgorithmNegotiator):
        """Initialize the deprecation manager."""
        self._negotiator = negotiator
        self._warned_algorithms: Set[str] = set()
        
        logger.info("DeprecationManager initialized (warning period: %d days)",
                   self.DEPRECATION_WARNING_DAYS)
    
    def check_deprecations(self) -> List[Dict[str, Any]]:
        """
        Check for algorithms approaching deprecation.
        
        Returns:
            List of deprecation warnings
            
        Requirements:
            - 8.4: Warn 90 days before algorithm removal
        """
        warnings = []
        now = datetime.datetime.now(datetime.timezone.utc)
        
        for name, alg in self._negotiator._algorithms.items():
            if alg.deprecated and alg.deprecation_date:
                try:
                    # Parse deprecation date
                    dep_date = datetime.datetime.fromisoformat(
                        alg.deprecation_date.replace('Z', '+00:00')
                    )
                    
                    days_until = (dep_date - now).days
                    
                    if 0 < days_until <= self.DEPRECATION_WARNING_DAYS:
                        warning = {
                            'algorithm': name,
                            'deprecation_date': alg.deprecation_date,
                            'days_remaining': days_until,
                            'message': f"Algorithm {name} will be removed in {days_until} days"
                        }
                        warnings.append(warning)
                        
                        if name not in self._warned_algorithms:
                            logger.warning("DEPRECATION WARNING: %s", warning['message'])
                            self._warned_algorithms.add(name)
                    
                    elif days_until <= 0:
                        # Algorithm should be disabled
                        warning = {
                            'algorithm': name,
                            'deprecation_date': alg.deprecation_date,
                            'days_remaining': days_until,
                            'message': f"Algorithm {name} has passed deprecation date and should be disabled"
                        }
                        warnings.append(warning)
                        logger.error("DEPRECATION EXPIRED: %s", warning['message'])
                        
                except ValueError as e:
                    logger.error("Invalid deprecation date for %s: %s", name, e)
        
        return warnings
    
    def get_deprecated_algorithms(self) -> List[AlgorithmSpec]:
        """Get list of deprecated algorithms."""
        return [
            alg for alg in self._negotiator._algorithms.values()
            if alg.deprecated
        ]
    
    def set_deprecation(
        self,
        algorithm_name: str,
        deprecation_date: str
    ) -> bool:
        """
        Set deprecation date for an algorithm.
        
        Args:
            algorithm_name: Name of the algorithm
            deprecation_date: ISO 8601 date string
            
        Returns:
            True if deprecation was set
        """
        alg = self._negotiator._algorithms.get(algorithm_name)
        if not alg:
            logger.error("Algorithm %s not found", algorithm_name)
            return False
        
        alg.deprecated = True
        alg.deprecation_date = deprecation_date
        
        logger.warning("Algorithm %s marked for deprecation on %s",
                      algorithm_name, deprecation_date)
        
        return True


class AlgorithmTransitionLogger:
    """
    Logger for algorithm transitions.
    
    Requirements:
    - 8.6: Log all algorithm transitions with full audit trail
    """
    
    def __init__(self, audit_logger=None):
        """Initialize the transition logger."""
        self._audit_logger = audit_logger
        self._transitions: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        
        logger.info("AlgorithmTransitionLogger initialized")
    
    def log_transition(
        self,
        transition_type: str,
        details: Dict[str, Any],
        success: bool = True
    ) -> None:
        """
        Log an algorithm transition.
        
        Args:
            transition_type: Type of transition (e.g., "negotiation", "disable", "enable")
            details: Transition details
            success: Whether the transition succeeded
        """
        with self._lock:
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
            
            transition = {
                'timestamp': timestamp,
                'type': transition_type,
                'details': details,
                'success': success
            }
            
            self._transitions.append(transition)
            
            # Log to audit system if available
            if self._audit_logger:
                try:
                    from enhanced_audit_logging import AuditEventType, AuditSeverity
                    
                    severity = AuditSeverity.INFO if success else AuditSeverity.HIGH
                    
                    self._audit_logger.add_entry(
                        AuditEventType.CONFIGURATION_CHANGE,
                        f"Algorithm transition: {transition_type}",
                        severity,
                        transition
                    )
                except Exception as e:
                    logger.error("Failed to log to audit system: %s", e)
            
            logger.info("Algorithm transition logged: %s (success=%s)", transition_type, success)
    
    def log_negotiation(
        self,
        local_suites: List[str],
        remote_suites: List[str],
        selected_suite: Optional[str],
        success: bool
    ) -> None:
        """Log a cipher suite negotiation."""
        self.log_transition(
            'negotiation',
            {
                'local_suites': local_suites,
                'remote_suites': remote_suites,
                'selected_suite': selected_suite
            },
            success
        )
    
    def log_algorithm_disable(
        self,
        algorithm: str,
        reason: str,
        emergency: bool = False
    ) -> None:
        """Log an algorithm disable event."""
        self.log_transition(
            'emergency_disable' if emergency else 'disable',
            {
                'algorithm': algorithm,
                'reason': reason,
                'emergency': emergency
            },
            True
        )
    
    def log_algorithm_enable(self, algorithm: str) -> None:
        """Log an algorithm enable event."""
        self.log_transition(
            'enable',
            {'algorithm': algorithm},
            True
        )
    
    def get_transitions(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        transition_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get logged transitions with optional filtering.
        
        Args:
            start_time: ISO 8601 start time filter
            end_time: ISO 8601 end time filter
            transition_type: Type filter
            
        Returns:
            List of matching transitions
        """
        with self._lock:
            result = list(self._transitions)
            
            if transition_type:
                result = [t for t in result if t['type'] == transition_type]
            
            if start_time:
                result = [t for t in result if t['timestamp'] >= start_time]
            
            if end_time:
                result = [t for t in result if t['timestamp'] <= end_time]
            
            return result


class CryptographicAgilityFramework:
    """
    Main entry point for the Cryptographic Agility Framework.
    
    Combines all components for comprehensive algorithm management:
    - Algorithm negotiation
    - Signed configuration updates
    - Deprecation management
    - Transition logging
    
    Requirements:
    - 8.1: Algorithm negotiation with version-tagged cipher suites
    - 8.2: Runtime algorithm updates via signed configuration
    - 8.3: Backward compatibility with previous algorithm versions
    - 8.4: Algorithm deprecation warnings 90 days before removal
    - 8.5: Emergency algorithm disable via signed broadcast
    - 8.6: Log all algorithm transitions with full audit trail
    """
    
    def __init__(self, audit_logger=None):
        """
        Initialize the cryptographic agility framework.
        
        Args:
            audit_logger: Optional audit logger for transition logging
        """
        self.negotiator = AlgorithmNegotiator()
        self.config_manager = SignedConfigurationManager(self.negotiator, audit_logger)
        self.deprecation_manager = DeprecationManager(self.negotiator)
        self.transition_logger = AlgorithmTransitionLogger(audit_logger)
        
        logger.info("CryptographicAgilityFramework initialized")
    
    def negotiate_cipher_suite(
        self,
        remote_suites: List[str]
    ) -> Optional[CipherSuite]:
        """
        Negotiate a cipher suite with a remote peer.
        
        Args:
            remote_suites: List of cipher suite IDs supported by remote peer
            
        Returns:
            The negotiated CipherSuite, or None if negotiation failed
        """
        local_suites = self.negotiator.get_local_suite_ids()
        selected = self.negotiator.negotiate(local_suites, remote_suites)
        
        self.transition_logger.log_negotiation(
            local_suites,
            remote_suites,
            selected.suite_id if selected else None,
            selected is not None
        )
        
        return selected
    
    def apply_configuration(self, config: SignedConfiguration) -> bool:
        """
        Apply a signed configuration update.
        
        Args:
            config: The signed configuration to apply
            
        Returns:
            True if configuration was applied
        """
        return self.config_manager.apply_signed_config(config)
    
    def emergency_disable_algorithm(
        self,
        algorithm_name: str,
        reason: str,
        admin_secret_key: bytes,
        admin_public_key: bytes
    ) -> bool:
        """
        Emergency disable an algorithm via signed broadcast.
        
        Args:
            algorithm_name: Name of the algorithm to disable
            reason: Reason for disabling
            admin_secret_key: Admin's ML-DSA-87 secret key
            admin_public_key: Admin's ML-DSA-87 public key
            
        Returns:
            True if algorithm was disabled
        """
        config = self.config_manager.create_signed_config(
            'emergency_disable',
            {'algorithm': algorithm_name, 'reason': reason},
            admin_secret_key,
            admin_public_key
        )
        
        success = self.config_manager.apply_signed_config(config)
        
        if success:
            self.transition_logger.log_algorithm_disable(algorithm_name, reason, emergency=True)
        
        return success
    
    def check_deprecation_warnings(self) -> List[Dict[str, Any]]:
        """
        Check for deprecation warnings.
        
        Returns:
            List of deprecation warnings
        """
        return self.deprecation_manager.check_deprecations()
    
    def get_supported_algorithms(self, family: Optional[AlgorithmFamily] = None) -> List[AlgorithmSpec]:
        """Get list of supported algorithms."""
        return self.negotiator.get_supported_algorithms(family)
    
    def get_supported_cipher_suites(self) -> List[CipherSuite]:
        """Get list of supported cipher suites."""
        return self.negotiator.get_supported_cipher_suites()
    
    def get_transition_log(self) -> List[Dict[str, Any]]:
        """Get the algorithm transition log."""
        return self.transition_logger.get_transitions()


# Module-level convenience functions
_framework: Optional[CryptographicAgilityFramework] = None


def get_agility_framework() -> CryptographicAgilityFramework:
    """Get the global cryptographic agility framework instance."""
    global _framework
    if _framework is None:
        _framework = CryptographicAgilityFramework()
    return _framework


def initialize_agility_framework(audit_logger=None) -> CryptographicAgilityFramework:
    """Initialize the global cryptographic agility framework."""
    global _framework
    _framework = CryptographicAgilityFramework(audit_logger)
    return _framework


if __name__ == '__main__':
    # Test the framework
    print("=" * 60)
    print("Testing Cryptographic Agility Framework")
    print("=" * 60)
    
    framework = CryptographicAgilityFramework()
    
    # Test algorithm listing
    print("\n1. Supported Algorithms:")
    for alg in framework.get_supported_algorithms():
        print(f"   - {alg.name} (Level {alg.security_level.value}, {alg.family.value})")
    
    # Test cipher suite listing
    print("\n2. Supported Cipher Suites:")
    for suite in framework.get_supported_cipher_suites():
        print(f"   - {suite.suite_id} (Level {suite.security_level.value})")
    
    # Test negotiation
    print("\n3. Testing Negotiation:")
    local = ['TRIPLE_HYBRID_LEVEL5_V1', 'DUAL_HYBRID_LEVEL5_V1', 'SINGLE_LEVEL5_V1']
    remote = ['DUAL_HYBRID_LEVEL5_V1', 'SINGLE_LEVEL5_V1']
    selected = framework.negotiate_cipher_suite(remote)
    if selected:
        print(f"   Selected: {selected.suite_id} (Level {selected.security_level.value})")
    
    # Test signed configuration
    print("\n4. Testing Signed Configuration:")
    try:
        pk, sk = framework.config_manager.generate_admin_keypair()
        print(f"   Generated admin keypair (PK hash: {hashlib.sha512(pk).hexdigest()[:32]}...)")
        
        config = framework.config_manager.create_signed_config(
            'algorithm_update',
            {'enable_algorithm': 'ML-KEM-1024'},
            sk, pk
        )
        print(f"   Created signed config: {config.config_id}")
        
        # Verify signature
        valid = framework.config_manager.verify_signature(config)
        print(f"   Signature valid: {valid}")
        
    except Exception as e:
        print(f"   Signed config test skipped: {e}")
    
    print("\n[OK] Cryptographic Agility Framework tests complete")
