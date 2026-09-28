"""
Key Encapsulation Mechanism (ML-KEM-1024).

Provides quantum-resistant key encapsulation operations using ML-KEM-1024
(NIST FIPS 203) with hybrid security combining lattice-based and code-based
cryptography.
"""

from typing import Tuple, Dict, Any
try:
    from ..base import BaseModule, CryptoError
except (ImportError, ValueError):
    from base import BaseModule, CryptoError


class KEMOperations(BaseModule):
    """Quantum-resistant KEM operations."""
    
    def __init__(self, orchestrator):
        """Initialize KEM operations."""
        super().__init__(orchestrator)
        self._kem_impl = None
    
    @property
    def kem_impl(self):
        """Lazy load KEM implementation."""
        if self._kem_impl is None:
            try:
                from pqc_algorithms import EnhancedMLKEM_1024
                self._kem_impl = EnhancedMLKEM_1024()
            except ImportError as e:
                self.logger.error(f"Failed to import ML-KEM-1024: {e}", exc_info=True)
                raise CryptoError(
                    f"Failed to load ML-KEM-1024 implementation: {e}",
                    module="crypto.kem",
                    function="kem_impl",
                    severity="CRITICAL"
                )
        return self._kem_impl
    
    def generate_kem_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate ML-KEM-1024 keypair.
        
        Generates a new public/private key pair for key encapsulation.
        Uses hybrid KEM combining ML-KEM-1024 (lattice-based) and
        McEliece-8192128f (code-based) for defense-in-depth.
        
        Returns:
            Tuple of (public_key, private_key) as bytes
            
        Raises:
            CryptoError: If keypair generation fails
        """
        try:
            self.logger.debug("Generating ML-KEM-1024 keypair")
            
            public_key, private_key = self.kem_impl.keygen()
            
            if not isinstance(public_key, bytes) or not isinstance(private_key, bytes):
                raise ValueError("Keys must be bytes")
            
            self.logger.debug(f"ML-KEM-1024 keypair generated (pk_len={len(public_key)}, sk_len={len(private_key)})")
            return public_key, private_key
            
        except Exception as e:
            self.logger.error(f"KEM keypair generation failed: {e}", exc_info=True)
            raise CryptoError(
                f"KEM keypair generation failed: {e}",
                module="crypto.kem",
                function="generate_kem_keypair",
                severity="HIGH"
            )
    
    def kem_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using ML-KEM-1024.
        
        Generates a ciphertext and shared secret using the recipient's
        public key. The ciphertext can be transmitted to the recipient
        who will decapsulate it using their private key.
        
        Args:
            public_key: Recipient's ML-KEM-1024 public key (bytes)
            
        Returns:
            Tuple of (ciphertext, shared_secret) as bytes
            
        Raises:
            CryptoError: If encapsulation fails
        """
        try:
            if not isinstance(public_key, bytes):
                raise TypeError("Public key must be bytes")
            
            self.logger.debug(f"Encapsulating shared secret with ML-KEM-1024 (pk_len={len(public_key)})")
            
            ciphertext, shared_secret = self.kem_impl.encaps(public_key)
            
            if not isinstance(ciphertext, bytes) or not isinstance(shared_secret, bytes):
                raise ValueError("Ciphertext and shared secret must be bytes")
            
            self.logger.debug(f"ML-KEM-1024 encapsulation successful (ct_len={len(ciphertext)}, ss_len={len(shared_secret)})")
            return ciphertext, shared_secret
            
        except TypeError as e:
            self.logger.error(f"Type error in KEM encapsulation: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for KEM encapsulation: {e}",
                module="crypto.kem",
                function="kem_encapsulate",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"KEM encapsulation failed: {e}", exc_info=True)
            raise CryptoError(
                f"KEM encapsulation failed: {e}",
                module="crypto.kem",
                function="kem_encapsulate",
                severity="HIGH"
            )
    
    def kem_decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """
        Decapsulate a shared secret using ML-KEM-1024.
        
        Recovers the shared secret from a ciphertext using the recipient's
        private key. Should produce the same shared secret as was generated
        during encapsulation.
        
        Args:
            ciphertext: ML-KEM-1024 ciphertext (bytes)
            private_key: Recipient's ML-KEM-1024 private key (bytes)
            
        Returns:
            Shared secret (bytes)
            
        Raises:
            CryptoError: If decapsulation fails
        """
        try:
            if not isinstance(ciphertext, bytes):
                raise TypeError("Ciphertext must be bytes")
            if not isinstance(private_key, bytes):
                raise TypeError("Private key must be bytes")
            
            self.logger.debug(f"Decapsulating shared secret with ML-KEM-1024 (ct_len={len(ciphertext)}, sk_len={len(private_key)})")
            
            shared_secret = self.kem_impl.decaps(private_key, ciphertext)
            
            if not isinstance(shared_secret, bytes):
                raise ValueError("Shared secret must be bytes")
            
            self.logger.debug(f"ML-KEM-1024 decapsulation successful (ss_len={len(shared_secret)})")
            return shared_secret
            
        except TypeError as e:
            self.logger.error(f"Type error in KEM decapsulation: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for KEM decapsulation: {e}",
                module="crypto.kem",
                function="kem_decapsulate",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"KEM decapsulation failed: {e}", exc_info=True)
            raise CryptoError(
                f"KEM decapsulation failed: {e}",
                module="crypto.kem",
                function="kem_decapsulate",
                severity="HIGH"
            )
    
    def ensure_hybrid_session_keys(self, peer_bundle: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure hybrid session keys are established.
        
        Performs hybrid key exchange combining classical and post-quantum
        algorithms to establish session keys with both classical and
        quantum-resistant security.
        
        Args:
            peer_bundle: Dictionary containing peer information including:
                - 'peer_id': Peer identifier
                - 'public_key': Peer's public key
                - 'ephemeral_public_key': Peer's ephemeral public key (optional)
                
        Returns:
            Dictionary containing:
                - 'session_key': Established session key
                - 'shared_secret': Shared secret from KEM
                - 'ciphertext': KEM ciphertext (if initiator)
                - 'peer_id': Peer identifier
                
        Raises:
            CryptoError: If key establishment fails
        """
        try:
            if not isinstance(peer_bundle, dict):
                raise TypeError("Peer bundle must be a dictionary")
            
            if 'public_key' not in peer_bundle:
                raise ValueError("Peer bundle must contain 'public_key'")
            
            peer_id = peer_bundle.get('peer_id', 'unknown')
            peer_public_key = peer_bundle['public_key']
            
            self.logger.debug(f"Establishing hybrid session keys with peer {peer_id}")
            
            # Perform KEM encapsulation to establish shared secret
            ciphertext, shared_secret = self.kem_encapsulate(peer_public_key)

            # 2028 hardening (NIST SP 800-227 s4.6 / CNSA 2.0 hybrid combiner):
            # never truncate raw shared secret. Approved KDF with domain
            # separation + peer binding. Raw shared_secret is still returned
            # for callers that re-derive, but session_key is HKDF output.
            # Unauthenticated helper: callers MUST verify peer_bundle
            # (Ed25519/FALCON + TOFU pin) via hybrid_kex.verify_public_bundle
            # before calling this function; see hybrid_kex.py:1840.
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            import hashlib
            peer_binding = hashlib.sha3_256(
                str(peer_id).encode("utf-8", errors="ignore") + bytes(peer_public_key)
            ).digest()
            session_key = HKDF(
                algorithm=hashes.SHA384(),
                length=32,
                salt=peer_binding,
                info=b"SecureP2P::HybridKEM::SessionKey::v1::CNSA2",
            ).derive(bytes(shared_secret))
            
            result = {
                'session_key': session_key,
                'shared_secret': shared_secret,
                'ciphertext': ciphertext,
                'peer_id': peer_id
            }
            
            self.logger.debug(f"Hybrid session keys established with peer {peer_id}")
            return result
            
        except TypeError as e:
            self.logger.error(f"Type error in hybrid session key establishment: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid input type for hybrid session keys: {e}",
                module="crypto.kem",
                function="ensure_hybrid_session_keys",
                severity="HIGH"
            )
        except ValueError as e:
            self.logger.error(f"Value error in hybrid session key establishment: {e}", exc_info=True)
            raise CryptoError(
                f"Invalid peer bundle for hybrid session keys: {e}",
                module="crypto.kem",
                function="ensure_hybrid_session_keys",
                severity="HIGH"
            )
        except Exception as e:
            self.logger.error(f"Hybrid session key establishment failed: {e}", exc_info=True)
            raise CryptoError(
                f"Hybrid session key establishment failed: {e}",
                module="crypto.kem",
                function="ensure_hybrid_session_keys",
                severity="HIGH"
            )


# ---------------------------------------------------------------------------
# PQXDH combiner v2 (versioned, non-breaking addition).
# ---------------------------------------------------------------------------
# needs-manual-review (interop): the salt preimage, info layout, 4-byte
# big-endian length-prefix framing, transcript-hash binding, HKDF-SHA384
# choice, and 32-byte output length below are interop-critical. Both peers
# MUST use byte-identical values/layouts or they will derive different keys.
# Any change to these constants creates a new protocol version; do NOT alter
# them in place. v1 (SHA3_512 concat combiner in hybrid_kex.py) is untouched.
HYBRID_X3DH_PQ_V2_SALT_LABEL = b"SecureP2P::HybridX3DH-PQ::v2::Salt::CNSA2"
HYBRID_X3DH_PQ_V2_INFO_LABEL = (
    b"SecureP2P::HybridX3DH-PQ::v2::X25519_ML-KEM-1024_McEliece_HKDF-SHA384"
)


def _v2_len_prefix(data: bytes) -> bytes:
    """4-byte big-endian length prefix + data (framing without ambiguity)."""
    import struct
    return struct.pack(">I", len(data)) + bytes(data)


def hybrid_combine_v2(dh_list: list, ss_hybrid: bytes, transcript: bytes) -> bytes:
    """Combine X25519 DH outputs + hybrid PQ secret into a 32-byte root key.

    Construction (v2):
      salt = SHA384(b"SecureP2P::HybridX3DH-PQ::v2::Salt::CNSA2")  [fixed]
      thash = SHA384(transcript)
      lens = b"".join(BE32(len(p)) for p in (DH1..DH4, ss_hybrid))
      info = INFO_LABEL + b"::Lens:" + lens + b"::TH:" + thash
      ikm  = b"".join(BE32(len(p)) + p for p in (DH1..DH4, ss_hybrid))
      sk   = HKDF-SHA384(salt=salt, info=info, length=32).derive(ikm)

    Length-prefixing every input avoids delimiter/concatenation ambiguity.
    The caller-supplied transcript (already domain-specific, see
    HybridKeyExchange.build_transcript_v2) is bound via its SHA384 digest in
    `info`, so any transcript mismatch (peer IDs, keys, ciphertext, role,
    opk flag) yields an unrelated output key.

    Security notes:
      - This function NEVER returns raw key material; only the 32-byte
        HKDF output is returned.
      - Memory: CPython `bytes` are immutable and CANNOT be wiped. This
        function copies the IKM into a local `bytearray`, derives, then
        zeroizes that mutable buffer. Callers holding DH outputs / ss in
        `bytearray` SHOULD wipe their own buffers after this call returns;
        wiping is best-effort for `bytes` inputs (a local mutable copy is
        wiped, the caller's immutable object cannot be).

    Args:
        dh_list: Exactly 4 non-empty bytes-like DH shared secrets (DH1..DH4).
        ss_hybrid: Non-empty hybrid PQ shared secret (e.g. ML-KEM+McEliece).
        transcript: Non-empty handshake transcript bytes (bound via hash).

    Returns:
        32-byte derived secret key.

    Raises:
        TypeError: On wrong input types.
        ValueError: On empty inputs or dh_list length != 4.
    """
    import hashlib
    import struct
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if not isinstance(dh_list, (list, tuple)) or len(dh_list) != 4:
        raise ValueError("dh_list must be a list/tuple of exactly 4 DH secrets (DH1..DH4)")
    parts = []
    for i, dh in enumerate(dh_list):
        if not isinstance(dh, (bytes, bytearray)):
            raise TypeError(f"dh_list[{i}] must be bytes-like, got {type(dh).__name__}")
        if len(dh) == 0:
            raise ValueError(f"dh_list[{i}] must be non-empty")
        parts.append(bytes(dh))
    if not isinstance(ss_hybrid, (bytes, bytearray)):
        raise TypeError(f"ss_hybrid must be bytes-like, got {type(ss_hybrid).__name__}")
    if len(ss_hybrid) == 0:
        raise ValueError("ss_hybrid must be non-empty")
    if not isinstance(transcript, (bytes, bytearray)):
        raise TypeError(f"transcript must be bytes-like, got {type(transcript).__name__}")
    if len(transcript) == 0:
        raise ValueError("transcript must be non-empty")
    parts.append(bytes(ss_hybrid))

    # Fixed domain-separated salt (public, interop-pinned; see header note).
    salt = hashlib.sha384(HYBRID_X3DH_PQ_V2_SALT_LABEL).digest()
    # Transcript bound via hash (raw transcript never enters the KDF directly).
    thash = hashlib.sha384(bytes(transcript)).digest()

    lens = b"".join(struct.pack(">I", len(p)) for p in parts)
    info = HYBRID_X3DH_PQ_V2_INFO_LABEL + b"::Lens:" + lens + b"::TH:" + thash

    # Mutable IKM buffer so it can be zeroized after derivation.
    ikm_buf = bytearray()
    for p in parts:
        ikm_buf += struct.pack(">I", len(p))
        ikm_buf += p

    try:
        sk = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=salt,
            info=info,
        ).derive(bytes(ikm_buf))
    finally:
        # Zeroize local mutable copies (caller's immutable `bytes` cannot
        # be wiped; see docstring).
        for i in range(len(ikm_buf)):
            ikm_buf[i] = 0

    if not isinstance(sk, bytes) or len(sk) != 32:
        raise ValueError("v2 combiner produced invalid output length")
    return sk
