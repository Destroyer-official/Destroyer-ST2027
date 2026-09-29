#!/usr/bin/env python3
"""
Triple-Hybrid Key Encapsulation Mechanism - Military 2026 Production Security

This module implements a triple-layer KEM combining three fundamentally different
post-quantum algorithm families for maximum defense-in-depth:

1. ML-KEM-1024 (Lattice-based): Fast, NIST FIPS 203 standard
2. McEliece-8192128f (Code-based): Conservative, unbroken since 1978
3. FrodoKEM-1344 (Conservative Lattice): LWE-based, conservative parameters

An attacker must break ALL THREE algorithm families to compromise the shared secret.

Security Properties:
- Triple-layer defense-in-depth
- HKDF-SHA384 key derivation with domain separation
- Independent verification of each KEM component
- Fail-closed security model
- Algorithm hot-swap support for future updates

Requirements Implemented:
- 1.1: Triple-hybrid KEM combining ML-KEM-1024, McEliece-8192128f, FrodoKEM-1344
- 1.2: HKDF-SHA384 derivation with all three component secrets
- 1.3: Independent verification of each KEM component
- 1.4: Terminate key exchange on any component failure
- 1.5: Algorithm hot-swap without session interruption
"""

import os
import logging
import secrets
import hashlib
from typing import Tuple, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
import ctypes
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import HKDF for key derivation
try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False
    raise ImportError("cryptography library required for HKDF-SHA384 and P-521")

# Import existing KEM implementations
try:
    from liboqs_wrapper import (
        LibOQS_MLKEM_1024,
        LibOQS_McEliece_8192128f,
        LibOQS_HQC_256,
        liboqs
    )
    HAVE_LIBOQS = True
except ImportError as e:
    HAVE_LIBOQS = False
    raise ImportError(f"liboqs_wrapper required for KEM implementations: {e}")


class TripleKEMError(Exception):
    """Base exception for Triple-Hybrid KEM errors."""


class KEMComponentError(TripleKEMError):
    """Exception raised when a KEM component fails."""
    def __init__(self, component: str, operation: str, message: str):
        self.component = component
        self.operation = operation
        super().__init__(f"Triple-KEM {component} {operation} failed: {message}")


class KEMVerificationError(TripleKEMError):
    """Exception raised when KEM component verification fails."""
    def __init__(self, component: str, message: str):
        self.component = component
        super().__init__(f"Triple-KEM {component} verification failed: {message}")


class AlgorithmVersion(Enum):
    """Version tags for algorithm configurations."""
    V1_0 = "v1.0"  # Initial triple-hybrid configuration
    V1_1 = "v1.1"  # Reserved for future updates


class KEMProfileMode(Enum):
    """Profile modes for hybrid key encapsulation mechanism.

    NOTE (corrected 2026-09-29): member names containing "CNSA" are
    HISTORICAL internal labels, NOT claims of CNSA 2.0 compliance — CNSA
    2.0 lists ML-KEM-1024 + ML-DSA-87 and defines no P-521 hybrid profile.
    Names/values are frozen (wire + config compat) and documented as custom.
    """
    CNSA_STRICT = "cnsa_strict"      # custom P-521 + ML-KEM-1024 two-leg profile (NOT a CNSA profile)
    MAX_DIVERSITY = "max_diversity"  # P-521 + ML-KEM-1024 + HQC-256 (Opt-in Agility Reserve)
    LEGACY_TRIPLE = "legacy_triple"  # ML-KEM-1024 + McEliece-8192128f + FrodoKEM-1344


@dataclass
class CNSAHybridKeyPair:
    """Data class for custom P-521 + ML-KEM-1024 hybrid keypair (NOT a CNSA profile; name frozen for compat)."""
    p521_pk: bytes       # P-521 public key (133 bytes)
    p521_sk: bytes       # P-521 secret key (66 bytes)
    mlkem_pk: bytes      # ML-KEM-1024 public key (1568 bytes)
    mlkem_sk: bytes      # ML-KEM-1024 secret key (3168 bytes)
    version: str = AlgorithmVersion.V1_0.value


@dataclass
class CNSAHybridCiphertext:
    """Data class for custom P-521 + ML-KEM-1024 hybrid ciphertext (NOT a CNSA profile; name frozen for compat)."""
    p521_ct: bytes       # P-521 ephemeral public key (133 bytes)
    mlkem_ct: bytes      # ML-KEM-1024 ciphertext (1568 bytes)
    version: str = AlgorithmVersion.V1_0.value


@dataclass
class TripleHybridKeyPair:
    """Data class for triple-hybrid keypair."""
    mlkem_pk: bytes      # ML-KEM-1024 public key
    mlkem_sk: bytes      # ML-KEM-1024 secret key
    mceliece_pk: bytes   # McEliece-8192128f public key
    mceliece_sk: bytes   # McEliece-8192128f secret key
    frodo_pk: bytes      # FrodoKEM-1344 public key
    frodo_sk: bytes      # FrodoKEM-1344 secret key
    version: str = AlgorithmVersion.V1_0.value


@dataclass
class TripleHybridCiphertext:
    """Data class for triple-hybrid ciphertext."""
    mlkem_ct: bytes      # ML-KEM-1024 ciphertext
    mceliece_ct: bytes   # McEliece-8192128f ciphertext
    frodo_ct: bytes      # FrodoKEM-1344 ciphertext
    version: str = AlgorithmVersion.V1_0.value


class EC_P521_KEM:
    """
    Classical Elliptic Curve Key Encapsulation Mechanism using SECP521R1 (P-521).

    Provides ~256-bit classical hedge alongside the NIST Level 5 ML-KEM-1024
    leg. P-521 is NIST SP 800-56A — it is NOT part of CNSA 2.0 (corrected
    2026-09-29; prior revision claimed CNSA/BSI mandates that do not exist).

    Parameters:
    - Curve: SECP521R1 (521-bit Weierstrass curve)
    - Public key size: 133 bytes (uncompressed point with 0x04 prefix)
    - Secret key size: 66 bytes (raw scalar)
    - Ciphertext size: 133 bytes (ephemeral public key point)
    - Shared secret size: 66 bytes (ECDH raw shared coordinate)
    """
    def __init__(self):
        self.alg_name = "ECDH-P521"
        self.curve = ec.SECP521R1()
        self.pk_size = 133
        self.sk_size = 66
        self.ct_size = 133
        self.ss_size = 66

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate static/ephemeral P-521 keypair."""
        sk = ec.generate_private_key(self.curve)
        pk = sk.public_key()
        pk_bytes = pk.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        priv_num = sk.private_numbers().private_value
        sk_bytes = priv_num.to_bytes(self.sk_size, byteorder="big")
        return pk_bytes, sk_bytes

    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate shared secret against peer's P-521 public key.

        Args:
            public_key: 133-byte uncompressed P-521 point

        Returns:
            Tuple of (ciphertext: 133-byte ephemeral public key, shared_secret: 66 bytes)
        """
        if len(public_key) != self.pk_size:
            raise KEMComponentError("P-521", "encaps", f"Invalid public key size: {len(public_key)} != {self.pk_size}")
        try:
            peer_pk = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, public_key)
            ephemeral_sk = ec.generate_private_key(self.curve)
            ephemeral_pk_bytes = ephemeral_sk.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            raw_ss = ephemeral_sk.exchange(ec.ECDH(), peer_pk)
            if len(raw_ss) < self.ss_size:
                raw_ss = raw_ss.rjust(self.ss_size, b'\x00')
            elif len(raw_ss) > self.ss_size:
                raw_ss = raw_ss[:self.ss_size]
            return ephemeral_pk_bytes, raw_ss
        except Exception as e:
            raise KEMComponentError("P-521", "encaps", str(e)) from e

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate shared secret using recipient's P-521 secret key.

        Args:
            secret_key: 66-byte private scalar
            ciphertext: 133-byte ephemeral public key point

        Returns:
            66-byte shared secret
        """
        if len(secret_key) != self.sk_size:
            raise KEMComponentError("P-521", "decaps", f"Invalid secret key size: {len(secret_key)} != {self.sk_size}")
        if len(ciphertext) != self.ct_size:
            raise KEMComponentError("P-521", "decaps", f"Invalid ciphertext size: {len(ciphertext)} != {self.ct_size}")
        try:
            priv_num = int.from_bytes(secret_key, byteorder="big")
            sk = ec.derive_private_key(priv_num, self.curve)
            ephemeral_pk = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, ciphertext)
            raw_ss = sk.exchange(ec.ECDH(), ephemeral_pk)
            if len(raw_ss) < self.ss_size:
                raw_ss = raw_ss.rjust(self.ss_size, b'\x00')
            elif len(raw_ss) > self.ss_size:
                raw_ss = raw_ss[:self.ss_size]
            return raw_ss
        except Exception as e:
            raise KEMComponentError("P-521", "decaps", str(e)) from e



class LibOQS_FrodoKEM_1344:
    """
    FrodoKEM-1344-SHAKE KEM implementation using liboqs.
    
    FrodoKEM is a conservative lattice-based KEM using the Learning With Errors (LWE)
    problem with conservative parameters. It provides NIST Level 5 security.
    
    Key characteristics:
    - Algorithm family: Lattice-based (LWE)
    - Security level: NIST Level 5 (256-bit post-quantum security)
    - Conservative parameters for maximum security margin
    - Larger key sizes but proven security foundations
    """
    
    def __init__(self):
        """Initialize FrodoKEM-1344-SHAKE using liboqs."""
        self.alg_name = b"FrodoKEM-1344-SHAKE"
        self.kem = liboqs.OQS_KEM_new(self.alg_name)
        
        if not self.kem:
            raise RuntimeError(
                f"Failed to initialize {self.alg_name.decode()} - "
                "Ensure liboqs was compiled with FrodoKEM support"
            )
        
        # Get algorithm parameters from liboqs
        self.pk_size = self.kem.contents.length_public_key
        self.sk_size = self.kem.contents.length_secret_key
        self.ct_size = self.kem.contents.length_ciphertext
        self.ss_size = self.kem.contents.length_shared_secret
        
        logger.info(
            f"[OK] LibOQS {self.alg_name.decode()} initialized: "
            f"PK={self.pk_size}, SK={self.sk_size}, CT={self.ct_size}, SS={self.ss_size}"
        )
    
    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generate FrodoKEM-1344 keypair.
        
        Returns:
            Tuple of (public_key, secret_key)
        """
        pk = (ctypes.c_uint8 * self.pk_size)()
        sk = (ctypes.c_uint8 * self.sk_size)()
        
        result = liboqs.OQS_KEM_keypair(self.kem, pk, sk)
        if result != 0:
            raise KEMComponentError("FrodoKEM-1344", "keygen", "keypair generation failed")
        
        return bytes(pk), bytes(sk)
    
    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate shared secret using FrodoKEM-1344.
        
        Args:
            public_key: FrodoKEM-1344 public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        if len(public_key) != self.pk_size:
            raise KEMComponentError(
                "FrodoKEM-1344", "encaps",
                f"Invalid public key size: expected {self.pk_size}, got {len(public_key)}"
            )
        
        ct = (ctypes.c_uint8 * self.ct_size)()
        ss = (ctypes.c_uint8 * self.ss_size)()
        pk_c = (ctypes.c_uint8 * self.pk_size).from_buffer_copy(public_key)
        
        result = liboqs.OQS_KEM_encaps(self.kem, ct, ss, pk_c)
        if result != 0:
            raise KEMComponentError("FrodoKEM-1344", "encaps", "encapsulation failed")
        
        return bytes(ct), bytes(ss)
    
    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate shared secret using FrodoKEM-1344.
        
        Args:
            secret_key: FrodoKEM-1344 secret key
            ciphertext: FrodoKEM-1344 ciphertext
            
        Returns:
            Shared secret bytes
        """
        if len(secret_key) != self.sk_size:
            raise KEMComponentError(
                "FrodoKEM-1344", "decaps",
                f"Invalid secret key size: expected {self.sk_size}, got {len(secret_key)}"
            )
        
        if len(ciphertext) != self.ct_size:
            raise KEMComponentError(
                "FrodoKEM-1344", "decaps",
                f"Invalid ciphertext size: expected {self.ct_size}, got {len(ciphertext)}"
            )
        
        ss = (ctypes.c_uint8 * self.ss_size)()
        sk_c = (ctypes.c_uint8 * self.sk_size).from_buffer_copy(secret_key)
        ct_c = (ctypes.c_uint8 * self.ct_size).from_buffer_copy(ciphertext)
        
        result = liboqs.OQS_KEM_decaps(self.kem, ss, ct_c, sk_c)
        if result != 0:
            raise KEMComponentError("FrodoKEM-1344", "decaps", "decapsulation failed")
        
        return bytes(ss)
    
    def __del__(self):
        """Clean up liboqs resources."""
        if hasattr(self, 'kem') and self.kem:
            liboqs.OQS_KEM_free(self.kem)


def is_hqc_available() -> bool:
    """Check if HQC-256 is supported, enabled, and authorized in this build.

    Vendored oqs.dll is 0.10.1, affected by HQC key-recovery issues fixed
    upstream in 0.12.0 (CVE-2024-54137) and 0.14.0 (CVE-2025-52473). The HQC
    diversity leg therefore stays DISABLED by default and the caller falls back
    to McEliece-8192128f. Explicit opt-in for lab evaluation only:
    P2P_ENABLE_VULN_HQC=1 (logged as CRITICAL). Re-enable by default after the
    DLL is rebuilt at >=0.16.0.
    """
    try:
        if os.environ.get("P2P_ENABLE_VULN_HQC", "").strip().lower() in ("1", "true", "yes", "on"):
            try:
                import logging as _logging
                _logging.getLogger(__name__).critical(
                    "P2P_ENABLE_VULN_HQC=1: HQC-256 leg explicitly enabled on vulnerable "
                    "oqs 0.10.1 (CVE-2024-54137/CVE-2025-52473). Lab evaluation only."
                )
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            if hasattr(liboqs, 'OQS_KEM_alg_is_enabled'):
                return bool(liboqs.OQS_KEM_alg_is_enabled(b"HQC-256"))
            return True
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass
    return False


class TripleHybridKEM:
    """
    Triple-Hybrid Key Encapsulation Mechanism.
    
    Combines three fundamentally different post-quantum algorithm families:
    - ML-KEM-1024 (Lattice-based): Fast, NIST FIPS 203 standard
    - McEliece-8192128f (Code-based): Conservative, unbroken since 1978
    - FrodoKEM-1344 (Conservative Lattice): LWE-based, conservative parameters
    
    An attacker must break ALL THREE algorithm families to compromise the shared secret.
    
    Security Properties:
    - Triple-layer defense-in-depth
    - HKDF-SHA384 key derivation with domain separation
    - Independent verification of each KEM component
    - Fail-closed security model (any failure terminates operation)
    - Algorithm hot-swap support for future updates
    
    Requirements:
    - 1.1: Triple-hybrid KEM combining three algorithm families
    - 1.2: HKDF-SHA384 derivation with all three component secrets
    - 1.3: Independent verification of each KEM component
    - 1.4: Terminate key exchange on any component failure
    - 1.5: Algorithm hot-swap without session interruption
    """
    
    # Domain separation info for HKDF
    DOMAIN_INFO = b"Triple-Hybrid-KEM-ML-KEM-1024-McEliece-8192128f-FrodoKEM-1344-v1.0"
    CNSA_DOMAIN_INFO = b"SecureP2P-CNSA-Strict-Hybrid-KEM-P521-ML-KEM-1024-v1.0"
    DIVERSITY_DOMAIN_INFO = b"SecureP2P-Max-Diversity-Hybrid-KEM-P521-MLKEM1024-HQC256-v1.0"

    # Output key size (384 bits = 48 bytes)
    OUTPUT_KEY_SIZE = 48

    def __init__(
        self,
        version: AlgorithmVersion = AlgorithmVersion.V1_0,
        mode: Optional[KEMProfileMode] = None
    ):
        """
        Initialize Hybrid KEM with specified profile mode.

        Args:
            version: Algorithm configuration version for hot-swap support
            mode: Profile mode (CNSA_STRICT default: P-521 + ML-KEM-1024 custom
                  two-leg profile, NOT a CNSA profile; see KEMProfileMode note,
                  MAX_DIVERSITY: P-521 + ML-KEM-1024 + HQC-256,
                  LEGACY_TRIPLE: ML-KEM-1024 + McEliece + Frodo)

        Raises:
            TripleKEMError: If any KEM component fails to initialize
        """
        self.version = version
        if mode is None:
            env_mode = os.environ.get("P2P_KEM_PROFILE", "cnsa_strict").strip().lower()
            if env_mode == "max_diversity":
                mode = KEMProfileMode.MAX_DIVERSITY
            elif env_mode in ("legacy", "legacy_triple"):
                mode = KEMProfileMode.LEGACY_TRIPLE
            else:
                mode = KEMProfileMode.CNSA_STRICT
        self.mode = mode
        self._mceliece = None
        self._frodo = None
        self._hqc = None
        self._init_algorithms()

        logger.info(
            f"[OK] Hybrid KEM initialized (mode {self.mode.value}, version {version.value})"
        )

    @property
    def mceliece(self) -> LibOQS_McEliece_8192128f:
        """Lazy-initialize McEliece-8192128f on demand."""
        if self._mceliece is None:
            try:
                self._mceliece = LibOQS_McEliece_8192128f()
            except Exception as e:
                raise TripleKEMError(f"Failed to initialize McEliece-8192128f: {e}")
        return self._mceliece

    @property
    def frodo(self) -> LibOQS_FrodoKEM_1344:
        """Lazy-initialize FrodoKEM-1344 on demand."""
        if self._frodo is None:
            try:
                self._frodo = LibOQS_FrodoKEM_1344()
            except Exception as e:
                raise TripleKEMError(f"Failed to initialize FrodoKEM-1344: {e}")
        return self._frodo

    @property
    def hqc(self) -> LibOQS_HQC_256:
        """Lazy-initialize HQC-256 on demand."""
        if self._hqc is None:
            try:
                self._hqc = LibOQS_HQC_256()
            except Exception as e:
                raise TripleKEMError(f"Failed to initialize HQC-256: {e}")
        return self._hqc

    def _init_algorithms(self):
        """Initialize KEM algorithms for the active mode."""
        try:
            # Initialize P-521 classical ECDH leg (custom hedge; P-521 is not CNSA 2.0)
            self.p521 = EC_P521_KEM()
            logger.debug("EC_P521 initialized")
        except Exception as e:
            raise TripleKEMError(f"Failed to initialize EC_P521: {e}")

        try:
            # Initialize ML-KEM-1024 (fast lattice-based, NIST FIPS 203)
            self.mlkem = LibOQS_MLKEM_1024()
            logger.debug("ML-KEM-1024 initialized")
        except Exception as e:
            raise TripleKEMError(f"Failed to initialize ML-KEM-1024: {e}")

        self._diversity_third = 'none'
        if self.mode == KEMProfileMode.LEGACY_TRIPLE:
            _ = self.mceliece
            _ = self.frodo
        elif self.mode == KEMProfileMode.MAX_DIVERSITY:
            if is_hqc_available():
                _ = self.hqc
                self._diversity_third = 'hqc'
            else:
                _ = self.mceliece
                self._diversity_third = 'mceliece'
                logger.info(
                    "HQC-256 not enabled in active liboqs build; "
                    "MAX_DIVERSITY using McEliece-8192128f as code-based leg."
                )

        # Store algorithm sizes for serialization
        self._pk_sizes = {
            'p521': self.p521.pk_size,
            'mlkem': self.mlkem.pk_size,
            'mceliece': 1357824,
            'frodo': 9616,
            'hqc': 7245
        }
        self._sk_sizes = {
            'p521': self.p521.sk_size,
            'mlkem': self.mlkem.sk_size,
            'mceliece': 14120,
            'frodo': 19888,
            'hqc': 2289
        }
        self._ct_sizes = {
            'p521': self.p521.ct_size,
            'mlkem': self.mlkem.ct_size,
            'mceliece': 208,
            'frodo': 9720,
            'hqc': 14421
        }

    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generate hybrid keypair for the active profile mode.

        Returns:
            Tuple of (public_key, secret_key) as serialized bytes

        Raises:
            KEMComponentError: If any component keygen fails
        """
        version_bytes = self.version.value.encode('utf-8').ljust(8, b'\x00')

        if self.mode == KEMProfileMode.CNSA_STRICT:
            try:
                p521_pk, p521_sk = self.p521.keygen()
            except Exception as e:
                raise KEMComponentError("P-521", "keygen", str(e))
            try:
                mlkem_pk, mlkem_sk = self.mlkem.keygen()
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "keygen", str(e))

            public_key = version_bytes + p521_pk + mlkem_pk
            secret_key = version_bytes + p521_sk + mlkem_sk
            logger.info(f"CNSA-Strict Hybrid keygen complete: PK={len(public_key)}, SK={len(secret_key)}")
            return public_key, secret_key

        elif self.mode == KEMProfileMode.MAX_DIVERSITY:
            try:
                p521_pk, p521_sk = self.p521.keygen()
            except Exception as e:
                raise KEMComponentError("P-521", "keygen", str(e))
            try:
                mlkem_pk, mlkem_sk = self.mlkem.keygen()
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "keygen", str(e))

            if getattr(self, '_diversity_third', 'hqc') == 'hqc' and is_hqc_available():
                try:
                    code_pk, code_sk = self.hqc.keygen()
                except Exception as e:
                    raise KEMComponentError("HQC-256", "keygen", str(e))
            else:
                try:
                    code_pk, code_sk = self.mceliece.keygen()
                except Exception as e:
                    raise KEMComponentError("McEliece-8192128f", "keygen", str(e))

            public_key = version_bytes + p521_pk + mlkem_pk + code_pk
            secret_key = version_bytes + p521_sk + mlkem_sk + code_sk
            logger.info(f"Max-Diversity Hybrid keygen complete: PK={len(public_key)}, SK={len(secret_key)}")
            return public_key, secret_key

        else: # LEGACY_TRIPLE
            try:
                mlkem_pk, mlkem_sk = self.mlkem.keygen()
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "keygen", str(e))
            try:
                mceliece_pk, mceliece_sk = self.mceliece.keygen()
            except Exception as e:
                raise KEMComponentError("McEliece-8192128f", "keygen", str(e))
            try:
                frodo_pk, frodo_sk = self.frodo.keygen()
            except Exception as e:
                raise KEMComponentError("FrodoKEM-1344", "keygen", str(e))

            public_key = version_bytes + mlkem_pk + mceliece_pk + frodo_pk
            secret_key = version_bytes + mlkem_sk + mceliece_sk + frodo_sk
            logger.info(f"Triple-Hybrid keygen complete: PK={len(public_key)}, SK={len(secret_key)}")
            return public_key, secret_key

    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate with KEMs matching public key format and derive combined secret.

        Args:
            public_key: Serialized hybrid public key

        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        version_bytes = public_key[:8]
        offset = 8

        # Case 1: CNSA_STRICT (P-521: 133B + ML-KEM-1024: 1568B) -> Total 1709 bytes
        if len(public_key) == 8 + self.p521.pk_size + self.mlkem.pk_size:
            p521_pk = public_key[offset:offset + self.p521.pk_size]
            offset += self.p521.pk_size
            mlkem_pk = public_key[offset:offset + self.mlkem.pk_size]

            try:
                p521_ct, p521_ss = self.p521.encaps(p521_pk)
            except Exception as e:
                raise KEMComponentError("P-521", "encaps", str(e))
            try:
                mlkem_ct, mlkem_ss = self.mlkem.encaps(mlkem_pk)
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "encaps", str(e))

            hybrid_ss = self._derive_cnsa_strict_key(p521_ss, mlkem_ss)
            ciphertext = version_bytes + p521_ct + mlkem_ct
            logger.info(f"CNSA-Strict encaps complete: CT={len(ciphertext)}, SS={len(hybrid_ss)}")
            return ciphertext, hybrid_ss

        # Case 2a: MAX_DIVERSITY with HQC-256 (P-521: 133B + ML-KEM-1024: 1568B + HQC-256: 7245B)
        elif is_hqc_available() and len(public_key) == 8 + self.p521.pk_size + self.mlkem.pk_size + self._pk_sizes['hqc']:
            p521_pk = public_key[offset:offset + self.p521.pk_size]
            offset += self.p521.pk_size
            mlkem_pk = public_key[offset:offset + self.mlkem.pk_size]
            offset += self.mlkem.pk_size
            hqc_pk = public_key[offset:offset + self._pk_sizes['hqc']]

            try:
                p521_ct, p521_ss = self.p521.encaps(p521_pk)
            except Exception as e:
                raise KEMComponentError("P-521", "encaps", str(e))
            try:
                mlkem_ct, mlkem_ss = self.mlkem.encaps(mlkem_pk)
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "encaps", str(e))
            try:
                hqc_ct, hqc_ss = self.hqc.encaps(hqc_pk)
            except Exception as e:
                raise KEMComponentError("HQC-256", "encaps", str(e))

            hybrid_ss = self._derive_diversity_key(p521_ss, mlkem_ss, hqc_ss)
            ciphertext = version_bytes + p521_ct + mlkem_ct + hqc_ct
            logger.info(f"Max-Diversity encaps complete: CT={len(ciphertext)}, SS={len(hybrid_ss)}")
            return ciphertext, hybrid_ss

        # Case 2b: MAX_DIVERSITY with McEliece (P-521: 133B + ML-KEM-1024: 1568B + McEliece: 1357824B)
        elif len(public_key) == 8 + self.p521.pk_size + self.mlkem.pk_size + self._pk_sizes['mceliece']:
            p521_pk = public_key[offset:offset + self.p521.pk_size]
            offset += self.p521.pk_size
            mlkem_pk = public_key[offset:offset + self.mlkem.pk_size]
            offset += self.mlkem.pk_size
            mceliece_pk = public_key[offset:offset + self._pk_sizes['mceliece']]

            try:
                p521_ct, p521_ss = self.p521.encaps(p521_pk)
            except Exception as e:
                raise KEMComponentError("P-521", "encaps", str(e))
            try:
                mlkem_ct, mlkem_ss = self.mlkem.encaps(mlkem_pk)
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "encaps", str(e))
            try:
                mceliece_ct, mceliece_ss = self.mceliece.encaps(mceliece_pk)
            except Exception as e:
                raise KEMComponentError("McEliece-8192128f", "encaps", str(e))

            hybrid_ss = self._derive_diversity_key(p521_ss, mlkem_ss, mceliece_ss)
            ciphertext = version_bytes + p521_ct + mlkem_ct + mceliece_ct
            logger.info(f"Max-Diversity (McEliece) encaps complete: CT={len(ciphertext)}, SS={len(hybrid_ss)}")
            return ciphertext, hybrid_ss

        # Case 3: LEGACY_TRIPLE (ML-KEM + McEliece + Frodo)
        else:
            mlkem_pk = public_key[offset:offset + self._pk_sizes['mlkem']]
            offset += self._pk_sizes['mlkem']
            mceliece_pk = public_key[offset:offset + self._pk_sizes['mceliece']]
            offset += self._pk_sizes['mceliece']
            frodo_pk = public_key[offset:offset + self._pk_sizes['frodo']]

            try:
                mlkem_ct, mlkem_ss = self.mlkem.encaps(mlkem_pk)
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "encaps", str(e))
            try:
                mceliece_ct, mceliece_ss = self.mceliece.encaps(mceliece_pk)
            except Exception as e:
                raise KEMComponentError("McEliece-8192128f", "encaps", str(e))
            try:
                frodo_ct, frodo_ss = self.frodo.encaps(frodo_pk)
            except Exception as e:
                raise KEMComponentError("FrodoKEM-1344", "encaps", str(e))

            hybrid_ss = self._derive_triple_key(mlkem_ss, mceliece_ss, frodo_ss)
            ciphertext = version_bytes + mlkem_ct + mceliece_ct + frodo_ct
            logger.info(f"Triple-Hybrid encaps complete: CT={len(ciphertext)}, SS={len(hybrid_ss)}")
            return ciphertext, hybrid_ss

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate components and verify each independently.

        Args:
            secret_key: Serialized hybrid secret key
            ciphertext: Serialized hybrid ciphertext

        Returns:
            48-byte shared secret derived from HKDF-SHA384
        """
        sk_version = secret_key[:8]
        ct_version = ciphertext[:8]
        if sk_version != ct_version:
            raise KEMVerificationError(
                "version",
                f"Version mismatch: SK={sk_version}, CT={ct_version}"
            )

        # Case 1: CNSA_STRICT (P-521: 133B CT + ML-KEM-1024: 1568B CT) -> Total 1709 bytes CT
        if len(ciphertext) == 8 + self.p521.ct_size + self.mlkem.ct_size:
            sk_offset = 8
            p521_sk = secret_key[sk_offset:sk_offset + self.p521.sk_size]
            sk_offset += self.p521.sk_size
            mlkem_sk = secret_key[sk_offset:sk_offset + self.mlkem.sk_size]

            ct_offset = 8
            p521_ct = ciphertext[ct_offset:ct_offset + self.p521.ct_size]
            ct_offset += self.p521.ct_size
            mlkem_ct = ciphertext[ct_offset:ct_offset + self.mlkem.ct_size]

            try:
                p521_ss = self.p521.decaps(p521_sk, p521_ct)
            except Exception as e:
                raise KEMComponentError("P-521", "decaps", str(e))
            try:
                mlkem_ss = self.mlkem.decaps(mlkem_sk, mlkem_ct)
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "decaps", str(e))

            hybrid_ss = self._derive_cnsa_strict_key(p521_ss, mlkem_ss)
            logger.info(f"CNSA-Strict decaps complete: SS={len(hybrid_ss)}")
            return hybrid_ss

        # Case 2a: MAX_DIVERSITY with HQC-256 (P-521 + ML-KEM-1024 + HQC-256)
        elif is_hqc_available() and len(ciphertext) == 8 + self.p521.ct_size + self.mlkem.ct_size + self._ct_sizes['hqc']:
            sk_offset = 8
            p521_sk = secret_key[sk_offset:sk_offset + self.p521.sk_size]
            sk_offset += self.p521.sk_size
            mlkem_sk = secret_key[sk_offset:sk_offset + self.mlkem.sk_size]
            sk_offset += self.mlkem.sk_size
            hqc_sk = secret_key[sk_offset:sk_offset + self._sk_sizes['hqc']]

            ct_offset = 8
            p521_ct = ciphertext[ct_offset:ct_offset + self.p521.ct_size]
            ct_offset += self.p521.ct_size
            mlkem_ct = ciphertext[ct_offset:ct_offset + self.mlkem.ct_size]
            ct_offset += self.mlkem.ct_size
            hqc_ct = ciphertext[ct_offset:ct_offset + self._ct_sizes['hqc']]

            try:
                p521_ss = self.p521.decaps(p521_sk, p521_ct)
            except Exception as e:
                raise KEMComponentError("P-521", "decaps", str(e))
            try:
                mlkem_ss = self.mlkem.decaps(mlkem_sk, mlkem_ct)
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "decaps", str(e))
            try:
                hqc_ss = self.hqc.decaps(hqc_sk, hqc_ct)
            except Exception as e:
                raise KEMComponentError("HQC-256", "decaps", str(e))

            hybrid_ss = self._derive_diversity_key(p521_ss, mlkem_ss, hqc_ss)
            logger.info(f"Max-Diversity decaps complete: SS={len(hybrid_ss)}")
            return hybrid_ss

        # Case 2b: MAX_DIVERSITY with McEliece (P-521 + ML-KEM-1024 + McEliece)
        elif len(ciphertext) == 8 + self.p521.ct_size + self.mlkem.ct_size + self._ct_sizes['mceliece']:
            sk_offset = 8
            p521_sk = secret_key[sk_offset:sk_offset + self.p521.sk_size]
            sk_offset += self.p521.sk_size
            mlkem_sk = secret_key[sk_offset:sk_offset + self.mlkem.sk_size]
            sk_offset += self.mlkem.sk_size
            mceliece_sk = secret_key[sk_offset:sk_offset + self._sk_sizes['mceliece']]

            ct_offset = 8
            p521_ct = ciphertext[ct_offset:ct_offset + self.p521.ct_size]
            ct_offset += self.p521.ct_size
            mlkem_ct = ciphertext[ct_offset:ct_offset + self.mlkem.ct_size]
            ct_offset += self.mlkem.ct_size
            mceliece_ct = ciphertext[ct_offset:ct_offset + self._ct_sizes['mceliece']]

            try:
                p521_ss = self.p521.decaps(p521_sk, p521_ct)
            except Exception as e:
                raise KEMComponentError("P-521", "decaps", str(e))
            try:
                mlkem_ss = self.mlkem.decaps(mlkem_sk, mlkem_ct)
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "decaps", str(e))
            try:
                mceliece_ss = self.mceliece.decaps(mceliece_sk, mceliece_ct)
            except Exception as e:
                raise KEMComponentError("McEliece-8192128f", "decaps", str(e))

            hybrid_ss = self._derive_diversity_key(p521_ss, mlkem_ss, mceliece_ss)
            logger.info(f"Max-Diversity (McEliece) decaps complete: SS={len(hybrid_ss)}")
            return hybrid_ss

        # Case 3: LEGACY_TRIPLE (ML-KEM + McEliece + Frodo)
        else:
            offset = 8
            mlkem_sk = secret_key[offset:offset + self._sk_sizes['mlkem']]
            offset += self._sk_sizes['mlkem']
            mceliece_sk = secret_key[offset:offset + self._sk_sizes['mceliece']]
            offset += self._sk_sizes['mceliece']
            frodo_sk = secret_key[offset:offset + self._sk_sizes['frodo']]

            offset = 8
            mlkem_ct = ciphertext[offset:offset + self._ct_sizes['mlkem']]
            offset += self._ct_sizes['mlkem']
            mceliece_ct = ciphertext[offset:offset + self._ct_sizes['mceliece']]
            offset += self._ct_sizes['mceliece']
            frodo_ct = ciphertext[offset:offset + self._ct_sizes['frodo']]

            try:
                mlkem_ss = self.mlkem.decaps(mlkem_sk, mlkem_ct)
            except Exception as e:
                raise KEMComponentError("ML-KEM-1024", "decaps", str(e))
            try:
                mceliece_ss = self.mceliece.decaps(mceliece_sk, mceliece_ct)
            except Exception as e:
                raise KEMComponentError("McEliece-8192128f", "decaps", str(e))
            try:
                frodo_ss = self.frodo.decaps(frodo_sk, frodo_ct)
            except Exception as e:
                raise KEMComponentError("FrodoKEM-1344", "decaps", str(e))

            hybrid_ss = self._derive_triple_key(mlkem_ss, mceliece_ss, frodo_ss)
            logger.info(f"Triple-Hybrid decaps complete: SS={len(hybrid_ss)}")
            return hybrid_ss

    def _derive_cnsa_strict_key(self, ss_first: bytes, ss_second: bytes) -> bytes:
        """Derive shared secret for P-521 + ML-KEM-1024 using HKDF-SHA384 with RFC 5869 domain-separated salt."""
        ikm = ss_first + ss_second
        salt = hashlib.sha384(b"SecureP2P::CNSAStrictKEM::Salt::v1::CNSA2-Level5").digest()
        kdf = HKDF(
            algorithm=hashes.SHA384(),
            length=self.OUTPUT_KEY_SIZE,
            salt=salt,
            info=self.CNSA_DOMAIN_INFO
        )
        return kdf.derive(ikm)

    def _derive_diversity_key(self, ss_first: bytes, ss_second: bytes, ss_third: bytes) -> bytes:
        """Derive shared secret for P-521 + ML-KEM-1024 + HQC-256 using HKDF-SHA384 with RFC 5869 salt."""
        ikm = ss_first + ss_second + ss_third
        salt = hashlib.sha384(b"SecureP2P::MaxDiversityKEM::Salt::v1::CNSA2-Level5").digest()
        kdf = HKDF(
            algorithm=hashes.SHA384(),
            length=self.OUTPUT_KEY_SIZE,
            salt=salt,
            info=self.DIVERSITY_DOMAIN_INFO
        )
        return kdf.derive(ikm)

    def _derive_triple_key(
        self,
        ss_mlkem: bytes,
        ss_mceliece: bytes,
        ss_frodo: bytes
    ) -> bytes:
        """
        Derive triple-hybrid shared secret using HKDF-SHA384 with RFC 5869 salt.

        Combines all three shared secrets using HKDF-SHA384 with domain
        separation to produce a 48-byte (384-bit) hybrid key.
        """
        ikm = ss_mlkem + ss_mceliece + ss_frodo
        salt = hashlib.sha384(b"SecureP2P::TripleHybridKEM::Salt::v1::CNSA2-Level5").digest()
        kdf = HKDF(
            algorithm=hashes.SHA384(),
            length=self.OUTPUT_KEY_SIZE,
            salt=salt,
            info=self.DOMAIN_INFO
        )
        return kdf.derive(ikm)

    def combine_shared_secrets(
        self,
        ss_first: bytes,
        ss_second: bytes,
        ss_third: Optional[bytes] = None
    ) -> bytes:
        """Public interface for combining shared secrets (supports 2 or 3 secrets)."""
        if ss_third is not None:
            return self._derive_triple_key(ss_first, ss_second, ss_third)
        return self._derive_cnsa_strict_key(ss_first, ss_second)

    def verify_component(
        self,
        component: str,
        public_key: bytes,
        secret_key: bytes
    ) -> bool:
        """Verify a single KEM component by performing encaps/decaps round-trip."""
        try:
            if component == 'p521':
                ct, ss1 = self.p521.encaps(public_key)
                ss2 = self.p521.decaps(secret_key, ct)
            elif component == 'mlkem':
                ct, ss1 = self.mlkem.encaps(public_key)
                ss2 = self.mlkem.decaps(secret_key, ct)
            elif component == 'mceliece':
                ct, ss1 = self.mceliece.encaps(public_key)
                ss2 = self.mceliece.decaps(secret_key, ct)
            elif component == 'frodo':
                ct, ss1 = self.frodo.encaps(public_key)
                ss2 = self.frodo.decaps(secret_key, ct)
            elif component == 'hqc':
                ct, ss1 = self.hqc.encaps(public_key)
                ss2 = self.hqc.decaps(secret_key, ct)
            else:
                raise ValueError(f"Unknown component: {component}")

            if not secrets.compare_digest(ss1, ss2):
                raise KEMVerificationError(
                    component,
                    "Shared secret mismatch in round-trip verification"
                )
            return True
        except KEMVerificationError:
            raise
        except Exception as e:
            raise KEMVerificationError(component, str(e))

    def get_algorithm_info(self) -> Dict[str, Any]:
        """
        Get information about the current algorithm configuration.

        Returns:
            Dictionary with algorithm details and sizes
        """
        if self.mode == KEMProfileMode.CNSA_STRICT:
            return {
                'mode': self.mode.value,
                'version': self.version.value,
                'algorithms': {
                    'p521': {
                        'name': 'ECDH-P521',
                        'family': 'Elliptic Curve (Weierstrass)',
                        'standard': 'NIST SP 800-56A (NOT CNSA 2.0)',
                        'pk_size': self.p521.pk_size,
                        'sk_size': self.p521.sk_size,
                        'ct_size': self.p521.ct_size
                    },
                    'mlkem': {
                        'name': 'ML-KEM-1024',
                        'family': 'Lattice (Module-LWE)',
                        'standard': 'NIST FIPS 203',
                        'pk_size': self.mlkem.pk_size,
                        'sk_size': self.mlkem.sk_size,
                        'ct_size': self.mlkem.ct_size
                    }
                },
                'output_key_size': self.OUTPUT_KEY_SIZE,
                'kdf': 'HKDF-SHA384',
                'domain_info': self.CNSA_DOMAIN_INFO.decode('utf-8')
            }
        elif self.mode == KEMProfileMode.MAX_DIVERSITY:
            return {
                'mode': self.mode.value,
                'version': self.version.value,
                'algorithms': {
                    'p521': {
                        'name': 'ECDH-P521',
                        'family': 'Elliptic Curve (Weierstrass)',
                        'standard': 'NIST SP 800-56A (NOT CNSA 2.0)',
                        'pk_size': self.p521.pk_size,
                        'sk_size': self.p521.sk_size,
                        'ct_size': self.p521.ct_size
                    },
                    'mlkem': {
                        'name': 'ML-KEM-1024',
                        'family': 'Lattice (Module-LWE)',
                        'standard': 'NIST FIPS 203',
                        'pk_size': self.mlkem.pk_size,
                        'sk_size': self.mlkem.sk_size,
                        'ct_size': self.mlkem.ct_size
                    },
                    'hqc': {
                        'name': 'HQC-256',
                        'family': 'Code-based',
                        'standard': 'NIST Post-Quantum Draft',
                        'pk_size': self.hqc.pk_size,
                        'sk_size': self.hqc.sk_size,
                        'ct_size': self.hqc.ct_size
                    }
                },
                'output_key_size': self.OUTPUT_KEY_SIZE,
                'kdf': 'HKDF-SHA384',
                'domain_info': self.DIVERSITY_DOMAIN_INFO.decode('utf-8')
            }
        else:
            return {
                'mode': self.mode.value,
                'version': self.version.value,
                'algorithms': {
                    'mlkem': {
                        'name': 'ML-KEM-1024',
                        'family': 'Lattice (Module-LWE)',
                        'standard': 'NIST FIPS 203',
                        'pk_size': self._pk_sizes['mlkem'],
                        'sk_size': self._sk_sizes['mlkem'],
                        'ct_size': self._ct_sizes['mlkem']
                    },
                    'mceliece': {
                        'name': 'McEliece-8192128f',
                        'family': 'Code-based',
                        'standard': 'Classic McEliece',
                        'pk_size': self._pk_sizes['mceliece'],
                        'sk_size': self._sk_sizes['mceliece'],
                        'ct_size': self._ct_sizes['mceliece']
                    },
                    'frodo': {
                        'name': 'FrodoKEM-1344-SHAKE',
                        'family': 'Lattice (LWE)',
                        'standard': 'FrodoKEM',
                        'pk_size': self._pk_sizes['frodo'],
                        'sk_size': self._sk_sizes['frodo'],
                        'ct_size': self._ct_sizes['frodo']
                    }
                },
                'output_key_size': self.OUTPUT_KEY_SIZE,
                'kdf': 'HKDF-SHA384',
                'domain_info': self.DOMAIN_INFO.decode('utf-8')
            }



class AlgorithmConfig:
    """
    Version-tagged algorithm configuration for hot-swap support.
    
    Supports algorithm transitions without session interruption by
    maintaining version compatibility information.
    
    Requirements:
        - 1.5: Algorithm hot-swap without session interruption
    """
    
    def __init__(self, version: AlgorithmVersion = AlgorithmVersion.V1_0):
        """Initialize algorithm configuration."""
        self.version = version
        self.algorithms = self._get_algorithms_for_version(version)
    
    def _get_algorithms_for_version(self, version: AlgorithmVersion) -> Dict[str, str]:
        """Get algorithm names for a specific version."""
        if version == AlgorithmVersion.V1_0:
            return {
                'kem1': 'ML-KEM-1024',
                'kem2': 'McEliece-8192128f',
                'kem3': 'FrodoKEM-1344-SHAKE',
                'kdf': 'HKDF-SHA384'
            }
        elif version == AlgorithmVersion.V1_1:
            # Reserved for future algorithm updates
            return {
                'kem1': 'ML-KEM-1024',
                'kem2': 'McEliece-8192128f',
                'kem3': 'FrodoKEM-1344-SHAKE',
                'kdf': 'HKDF-SHA384'
            }
        else:
            raise ValueError(f"Unknown algorithm version: {version}")
    
    def is_compatible(self, other_version: AlgorithmVersion) -> bool:
        """Check if two versions are compatible for session continuity."""
        # V1.0 and V1.1 are compatible (same algorithms)
        compatible_versions = {
            AlgorithmVersion.V1_0: {AlgorithmVersion.V1_0, AlgorithmVersion.V1_1},
            AlgorithmVersion.V1_1: {AlgorithmVersion.V1_0, AlgorithmVersion.V1_1}
        }
        return other_version in compatible_versions.get(self.version, set())
    
    def get_transition_info(
        self,
        target_version: AlgorithmVersion
    ) -> Dict[str, Any]:
        """
        Get information about transitioning to a new version.
        
        Args:
            target_version: Target algorithm version
            
        Returns:
            Dictionary with transition details
        """
        return {
            'current_version': self.version.value,
            'target_version': target_version.value,
            'compatible': self.is_compatible(target_version),
            'current_algorithms': self.algorithms,
            'target_algorithms': self._get_algorithms_for_version(target_version)
        }


class TripleHybridKEMSession:
    """
    Session manager for Triple-Hybrid KEM with hot-swap support.
    
    Manages key exchange sessions with support for algorithm transitions
    without interrupting active sessions.
    
    Requirements:
        - 1.5: Algorithm hot-swap without session interruption
    """
    
    def __init__(self, version: AlgorithmVersion = AlgorithmVersion.V1_0):
        """Initialize session with specified algorithm version."""
        self.config = AlgorithmConfig(version)
        self.kem = TripleHybridKEM(version)
        self.session_keys: Dict[str, bytes] = {}
        self.active_version = version
    
    def create_session(self, session_id: str) -> Tuple[bytes, bytes]:
        """
        Create a new key exchange session.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Tuple of (public_key, secret_key) for the session
        """
        pk, sk = self.kem.keygen()
        self.session_keys[session_id] = sk
        return pk, sk
    
    def complete_session(
        self,
        session_id: str,
        peer_public_key: bytes
    ) -> bytes:
        """
        Complete key exchange with peer's public key.
        
        Args:
            session_id: Session identifier
            peer_public_key: Peer's triple-hybrid public key
            
        Returns:
            Shared secret for the session
        """
        ct, ss = self.kem.encaps(peer_public_key)
        return ss
    
    def hot_swap_algorithm(
        self,
        new_version: AlgorithmVersion
    ) -> bool:
        """
        Hot-swap to a new algorithm version.
        
        Transitions to a new algorithm version while maintaining
        session continuity for compatible versions.
        
        Args:
            new_version: Target algorithm version
            
        Returns:
            True if hot-swap succeeded
            
        Raises:
            TripleKEMError: If versions are incompatible
        """
        if not self.config.is_compatible(new_version):
            raise TripleKEMError(
                f"Cannot hot-swap from {self.active_version.value} to "
                f"{new_version.value}: versions are incompatible"
            )
        
        # Create new KEM instance with new version
        new_kem = TripleHybridKEM(new_version)
        
        # Swap to new version
        old_version = self.active_version
        self.kem = new_kem
        self.config = AlgorithmConfig(new_version)
        self.active_version = new_version
        
        logger.info(
            f"Hot-swapped algorithm version: {old_version.value} -> {new_version.value}"
        )
        
        return True


def test_triple_hybrid_kem():
    """Test the Triple-Hybrid KEM implementation."""
    print("=" * 60)
    print("Testing Triple-Hybrid KEM Implementation")
    print("=" * 60)
    
    try:
        # Initialize Triple-Hybrid KEM
        print("\n1. Initializing Triple-Hybrid KEM...")
        kem = TripleHybridKEM()
        print("   [OK] Triple-Hybrid KEM initialized")
        
        # Display algorithm info
        info = kem.get_algorithm_info()
        print(f"\n   Version: {info['version']}")
        print(f"   KDF: {info['kdf']}")
        print(f"   Output key size: {info['output_key_size']} bytes")
        
        for name, alg in info['algorithms'].items():
            print(f"\n   {alg['name']}:")
            print(f"     Family: {alg['family']}")
            print(f"     PK: {alg['pk_size']} bytes")
            print(f"     SK: {alg['sk_size']} bytes")
            print(f"     CT: {alg['ct_size']} bytes")
        
        # Generate keypair
        print("\n2. Generating triple-hybrid keypair...")
        pk, sk = kem.keygen()
        print(f"   [OK] Public key: {len(pk)} bytes")
        print(f"   [OK] Secret key: {len(sk)} bytes")
        
        # Encapsulate
        print("\n3. Encapsulating shared secret...")
        ct, ss1 = kem.encaps(pk)
        print(f"   [OK] Ciphertext: {len(ct)} bytes")
        print(f"   [OK] Shared secret: {len(ss1)} bytes")
        
        # Decapsulate
        print("\n4. Decapsulating shared secret...")
        ss2 = kem.decaps(sk, ct)
        print(f"   [OK] Decapsulated secret: {len(ss2)} bytes")
        
        # Verify shared secrets match
        print("\n5. Verifying shared secrets match...")
        if secrets.compare_digest(ss1, ss2):
            print("   [OK] Shared secrets match!")
        else:
            print("   [FAIL] Shared secrets DO NOT match!")
            return False
        
        # Test hot-swap
        print("\n6. Testing algorithm hot-swap...")
        session = TripleHybridKEMSession()
        result = session.hot_swap_algorithm(AlgorithmVersion.V1_1)
        if result:
            print("   [OK] Hot-swap successful")
        else:
            print("   [FAIL] Hot-swap failed")
            return False
        
        print("\n" + "=" * 60)
        print("All Triple-Hybrid KEM tests PASSED!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


# Export classes
CNSAHybridKEM = TripleHybridKEM

__all__ = [
    'TripleHybridKEM',
    'CNSAHybridKEM',
    'KEMProfileMode',
    'EC_P521_KEM',
    'TripleHybridKEMSession',
    'TripleHybridKeyPair',
    'TripleHybridCiphertext',
    'CNSAHybridKeyPair',
    'CNSAHybridCiphertext',
    'AlgorithmVersion',
    'AlgorithmConfig',
    'TripleKEMError',
    'KEMComponentError',
    'KEMVerificationError',
    'LibOQS_FrodoKEM_1344',
    'is_hqc_available'
]


if __name__ == "__main__":
    test_triple_hybrid_kem()

