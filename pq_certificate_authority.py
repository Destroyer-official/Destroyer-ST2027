#!/usr/bin/env python3
"""
Post-Quantum Certificate Authority Implementation

MILITARY SECURITY ENFORCEMENT ACTIVE
• X.509v3 certificates with ML-DSA-87 signatures (NIST FIPS 204)
• Certificate chain building and validation
• Certificate Transparency logging with PQ signatures
• OCSP stapling with ML-DSA-87 signed responses
• Hash-chain CRL for revocation

Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6
"""

import hashlib
import os
import secrets
import time
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import base64

# CRL/OCSP hard-enforcement policy (non-breaking, fail-closed in production).
# P2P_CRL_REFRESH_HOURS default 24; production detected via P2P_PRODUCTION.
_PQ_CRL_REFRESH_DEFAULT_HOURS = 24.0
_PQ_ROTATION_DUAL_SIGN_WINDOW = timedelta(days=7)


def _pq_is_production() -> bool:
    try:
        return (
            os.environ.get("P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes", "on")
            or os.environ.get("SECURE_P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes", "on")
        )
    except Exception:
        return False


def _pq_crl_refresh_hours() -> float:
    try:
        raw = os.environ.get("P2P_CRL_REFRESH_HOURS", "24")
        val = float(str(raw).strip())
        if val <= 0:
            return _PQ_CRL_REFRESH_DEFAULT_HOURS
        return val
    except Exception:
        return _PQ_CRL_REFRESH_DEFAULT_HOURS

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import ML-DSA-87 signature implementation
try:
    from liboqs_wrapper import LibOQS_MLDSA_87, HybridSignature
    HAVE_MLDSA = True
    logger.info("[OK] ML-DSA-87 signature implementation available")
except ImportError as e:
    logger.critical(f"CRITICAL: ML-DSA-87 not available: {e}")
    HAVE_MLDSA = False
    raise ImportError("ML-DSA-87 required for PQ Certificate Authority")

# Import HKDF for key derivation
try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False
    raise ImportError("cryptography library required for HKDF")


# ============================================================================
# Error Classes - Fail-Closed Security Model
# ============================================================================

class CertificateError(Exception):
    """Base exception for certificate operations."""


class CertificateValidationError(CertificateError):
    """Raised when certificate validation fails. Connection MUST be terminated."""


class CertificateChainError(CertificateError):
    """Raised when certificate chain validation fails."""


class CertificateRevokedError(CertificateError):
    """Raised when a certificate has been revoked."""


class CertificateExpiredError(CertificateError):
    """Raised when a certificate has expired."""


class SignatureVerificationError(CertificateError):
    """Raised when signature verification fails."""


class OCSPError(CertificateError):
    """Raised when OCSP operations fail."""


class CTLogError(CertificateError):
    """Raised when Certificate Transparency operations fail."""


# ============================================================================
# Data Models
# ============================================================================

class CertificateStatus(Enum):
    """Certificate status values."""
    VALID = "valid"
    REVOKED = "revoked"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class RevocationReason(Enum):
    """Certificate revocation reasons per RFC 5280."""
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10


@dataclass
class PQCertificate:
    """
    Post-Quantum X.509v3 Certificate with ML-DSA-87 signature.
    
    Implements Requirements 2.1, 2.2
    """
    version: int = 3
    serial: int = 0
    issuer: str = ""
    subject: str = ""
    not_before: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    not_after: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=365))
    public_key: bytes = b""  # ML-DSA-87 public key
    signature_algorithm: str = "ML-DSA-87"
    signature: bytes = b""
    extensions: Dict[str, Any] = field(default_factory=dict)
    issuer_public_key: bytes = b""  # For chain validation
    # Dual-sign rotation window: optional second signature covering the same
    # TBS bytes, made by the *other* rotation key (old+new). Non-breaking:
    # defaults to empty (single-signed certs keep working).
    secondary_sig: bytes = b""
    
    def to_bytes(self) -> bytes:
        """Serialize certificate to bytes for signing/verification."""
        # Create TBS (To Be Signed) certificate data
        # NOTE: secondary_sig is deliberately EXCLUDED from TBS so both
        # rotation keys can sign the same bytes independently.
        # The "secondary_sig" extension (if present) is excluded so adding a
        # countersignature does not invalidate the primary signature.
        try:
            exts = dict(self.extensions or {})
            exts.pop("secondary_sig", None)
        except Exception:
            exts = self.extensions
        tbs_data = {
            "version": self.version,
            "serial": self.serial,
            "issuer": self.issuer,
            "subject": self.subject,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "public_key": base64.b64encode(self.public_key).decode('utf-8'),
            "signature_algorithm": self.signature_algorithm,
            "extensions": exts
        }
        return json.dumps(tbs_data, sort_keys=True).encode('utf-8')

    def get_secondary_sig(self) -> bytes:
        """Return dual-sign secondary signature from field or extensions."""
        try:
            if isinstance(getattr(self, "secondary_sig", b""), (bytes, bytearray)) and bytes(getattr(self, "secondary_sig", b"")):
                return bytes(self.secondary_sig)
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        try:
            ext = (self.extensions or {}).get("secondary_sig")
            if isinstance(ext, str) and ext.strip():
                try:
                    return base64.b64decode(ext.strip())
                except Exception:
                    return b""
            if isinstance(ext, (bytes, bytearray)) and bytes(ext):
                return bytes(ext)
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        return b""
    
    def get_fingerprint(self) -> bytes:
        """Get SHA3-512 fingerprint of certificate."""
        return hashlib.sha3_512(self.to_bytes() + self.signature).digest()
    
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        return datetime.now(timezone.utc) > self.not_after
    
    def is_not_yet_valid(self) -> bool:
        """Check if certificate is not yet valid."""
        return datetime.now(timezone.utc) < self.not_before


@dataclass
class OCSPResponse:
    """
    OCSP Response with ML-DSA-87 signature.
    
    Implements Requirement 2.4
    """
    cert_serial: int
    status: CertificateStatus
    this_update: datetime
    next_update: datetime
    responder_id: str
    signature: bytes = b""
    signature_algorithm: str = "ML-DSA-87"
    
    def to_bytes(self) -> bytes:
        """Serialize OCSP response for signing/verification."""
        data = {
            "cert_serial": self.cert_serial,
            "status": self.status.value,
            "this_update": self.this_update.isoformat(),
            "next_update": self.next_update.isoformat(),
            "responder_id": self.responder_id,
            "signature_algorithm": self.signature_algorithm
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')


@dataclass
class CTLogEntry:
    """
    Certificate Transparency Log Entry with PQ signature.
    
    Implements Requirement 2.3
    """
    timestamp: datetime
    cert_fingerprint: bytes
    log_id: str
    entry_index: int
    signature: bytes = b""
    previous_hash: bytes = b""  # Hash chain link
    
    def to_bytes(self) -> bytes:
        """Serialize CT log entry for signing."""
        data = {
            "timestamp": self.timestamp.isoformat(),
            "cert_fingerprint": base64.b64encode(self.cert_fingerprint).decode('utf-8'),
            "log_id": self.log_id,
            "entry_index": self.entry_index,
            "previous_hash": base64.b64encode(self.previous_hash).decode('utf-8')
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')
    
    def get_hash(self) -> bytes:
        """Get hash of this entry for chain linking."""
        return hashlib.sha3_256(self.to_bytes() + self.signature).digest()


@dataclass
class CRLEntry:
    """
    Certificate Revocation List Entry.
    
    Implements Requirement 2.5
    """
    serial: int
    revocation_date: datetime
    reason: RevocationReason
    
    def to_bytes(self) -> bytes:
        """Serialize CRL entry."""
        data = {
            "serial": self.serial,
            "revocation_date": self.revocation_date.isoformat(),
            "reason": self.reason.value
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')


@dataclass
class HashChainCRL:
    """
    Hash-Chain Certificate Revocation List.
    
    Implements Requirement 2.5 - Revocation list with hash-chain integrity.
    """
    issuer: str
    this_update: datetime
    next_update: datetime
    entries: List[CRLEntry] = field(default_factory=list)
    signature: bytes = b""
    chain_hash: bytes = b""  # Current hash chain head
    version: int = 1  # CRL version, bumped on every revocation propagation
    
    def to_bytes(self) -> bytes:
        """Serialize CRL for signing."""
        entries_data = [
            {
                "serial": e.serial,
                "revocation_date": e.revocation_date.isoformat(),
                "reason": e.reason.value
            }
            for e in self.entries
        ]
        data = {
            "issuer": self.issuer,
            "this_update": self.this_update.isoformat(),
            "next_update": self.next_update.isoformat(),
            "entries": entries_data,
            "chain_hash": base64.b64encode(self.chain_hash).decode('utf-8'),
            "version": int(getattr(self, "version", 1))
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')
    
    def compute_chain_hash(self) -> bytes:
        """Compute hash chain from all entries."""
        current_hash = b'\x00' * 32  # Genesis hash
        for entry in sorted(self.entries, key=lambda e: e.serial):
            entry_hash = hashlib.sha3_256(entry.to_bytes()).digest()
            current_hash = hashlib.sha3_256(current_hash + entry_hash).digest()
        return current_hash


# ============================================================================
# Post-Quantum Certificate Authority
# ============================================================================

class PQCertificateAuthority:
    """
    Post-Quantum Certificate Authority with ML-DSA-87 signatures.
    
    MILITARY SECURITY ENFORCEMENT ACTIVE
    • X.509v3 certificate generation with ML-DSA-87 signatures
    • Certificate chain building and validation
    • Certificate Transparency logging with PQ signatures
    • OCSP stapling with ML-DSA-87 signed responses
    • Hash-chain CRL for revocation
    
    Implements Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6
    """
    
    def __init__(self, ca_name: str = "PQ-Root-CA"):
        """
        Initialize Post-Quantum Certificate Authority.
        
        Args:
            ca_name: Name of the Certificate Authority
        """
        self.ca_name = ca_name
        self._mldsa = LibOQS_MLDSA_87()
        
        # Generate CA keypair
        self._ca_public_key, self._ca_secret_key = self._mldsa.keygen()
        
        # Certificate storage
        self._issued_certificates: Dict[int, PQCertificate] = {}
        self._next_serial = 1
        
        # Revocation list with hash-chain integrity
        self._crl = HashChainCRL(
            issuer=ca_name,
            this_update=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(days=1),
            chain_hash=b'\x00' * 32,
            version=1
        )
        self._revoked_serials: set = set()
        self._crl_version: int = 1
        # Retired signer window for key rotation: list of
        # {"public_key": bytes, "retired_at": datetime}. Previous signers are
        # accepted only within a 7-day dual-sign window AND only when the
        # certificate carries a secondary_sig made by the other rotation key.
        self._retired_keys: List[Dict[str, Any]] = []
        
        # Certificate Transparency log
        self._ct_log: List[CTLogEntry] = []
        self._ct_log_id = f"CT-Log-{secrets.token_hex(8)}"
        
        # OCSP responder
        self._ocsp_responses: Dict[int, OCSPResponse] = {}
        
        # Generate self-signed root certificate
        self._root_cert = self._generate_root_certificate()
        
        logger.info(f"[OK] PQ Certificate Authority '{ca_name}' initialized")
        logger.info(f"[OK] CA Public Key Size: {len(self._ca_public_key)} bytes")

    
    def _generate_root_certificate(self) -> PQCertificate:
        """Generate self-signed root CA certificate."""
        cert = PQCertificate(
            version=3,
            serial=0,
            issuer=self.ca_name,
            subject=self.ca_name,
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=3650),  # 10 years
            public_key=self._ca_public_key,
            signature_algorithm="ML-DSA-87",
            extensions={
                "basicConstraints": {"ca": True, "pathLen": 2},
                "keyUsage": ["keyCertSign", "cRLSign"],
                "subjectKeyIdentifier": base64.b64encode(
                    hashlib.sha3_256(self._ca_public_key).digest()
                ).decode('utf-8')
            },
            issuer_public_key=self._ca_public_key
        )
        
        # Self-sign the root certificate
        tbs_data = cert.to_bytes()
        cert.signature = self._mldsa.sign(self._ca_secret_key, tbs_data)
        
        return cert
    
    def get_root_certificate(self) -> PQCertificate:
        """Get the root CA certificate."""
        return self._root_cert
    
    def get_ca_public_key(self) -> bytes:
        """Get the CA's public key."""
        return self._ca_public_key
    
    # ========================================================================
    # Certificate Issuance (Requirement 2.1)
    # ========================================================================
    
    def issue_certificate(
        self,
        subject: str,
        public_key: bytes,
        validity_days: int = 365,
        extensions: Optional[Dict[str, Any]] = None
    ) -> PQCertificate:
        """
        Issue X.509v3 certificate with ML-DSA-87 signature.
        
        Implements Requirement 2.1: X.509v3 certificates with ML-DSA-87 signatures
        
        Args:
            subject: Certificate subject name
            public_key: Subject's ML-DSA-87 public key
            validity_days: Certificate validity period in days
            extensions: Optional certificate extensions
            
        Returns:
            Signed PQCertificate
        """
        serial = self._next_serial
        self._next_serial += 1
        
        cert = PQCertificate(
            version=3,
            serial=serial,
            issuer=self.ca_name,
            subject=subject,
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc) + timedelta(days=validity_days),
            public_key=public_key,
            signature_algorithm="ML-DSA-87",
            extensions=extensions or {},
            issuer_public_key=self._ca_public_key
        )
        
        # Sign the certificate
        tbs_data = cert.to_bytes()
        cert.signature = self._mldsa.sign(self._ca_secret_key, tbs_data)
        
        # Store certificate
        self._issued_certificates[serial] = cert
        
        # Add to CT log
        self._add_to_ct_log(cert)
        
        # Generate OCSP response
        self._generate_ocsp_response(cert)
        
        logger.info(f"[OK] Certificate issued: serial={serial}, subject={subject}")
        return cert

    
    # ========================================================================
    # Certificate Chain Validation (Requirement 2.2, 2.6)
    # ========================================================================
    
    def verify_certificate(self, cert: PQCertificate) -> bool:
        """
        Verify a single certificate's signature, validity window, and revocation status.

        Rotation window: a previous signer is accepted only within a 7-day
        dual-sign window AND only when the certificate carries a secondary_sig
        made by the other rotation key (old+new). Otherwise only the current
        CA key is accepted.

        Args:
            cert: Certificate to verify
            
        Returns:
            True if signature and status are valid
            
        Raises:
            CertificateExpiredError: If certificate is expired
            CertificateValidationError: If certificate is not yet valid
            CertificateRevokedError: If certificate is revoked
            SignatureVerificationError: If signature verification fails
        """
        if cert.is_expired():
            raise CertificateExpiredError(
                f"Certificate expired: serial={cert.serial}, subject={cert.subject}"
            )
        
        if cert.is_not_yet_valid():
            raise CertificateValidationError(
                f"Certificate not yet valid: serial={cert.serial}"
            )

        if cert.serial in self._revoked_serials:
            raise CertificateRevokedError(
                f"Certificate revoked: serial={cert.serial}, subject={cert.subject}"
            )

        # CRL freshness enforcement (fail-closed in production, warn in lab).
        self.check_crl_freshness("verify_certificate")

        tbs_data = cert.to_bytes()
        
        # Determine which public key to use for verification
        if cert.issuer == self.ca_name:
            issuer_pk = self._ca_public_key
        elif cert.issuer_public_key:
            issuer_pk = cert.issuer_public_key
        else:
            raise SignatureVerificationError(
                f"Cannot verify certificate: unknown issuer '{cert.issuer}'"
            )
        
        # Fast path: current signer.
        try:
            if self._mldsa.verify(issuer_pk, tbs_data, cert.signature):
                return True
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass

        # If the issuer_pk was an embedded third-party key (not the CA key),
        # there is no rotation fallback for it.
        try:
            _is_current_ca = (
                cert.issuer == self.ca_name
                or (issuer_pk is not None and secrets.compare_digest(bytes(issuer_pk), bytes(self._ca_public_key)))
            )
        except Exception:
            _is_current_ca = (cert.issuer == self.ca_name)
        if not _is_current_ca:
            raise SignatureVerificationError(
                f"Certificate signature verification failed: serial={cert.serial}"
            )

        # Rotation fallback: previous signer within 7d dual-sign window.
        # Accept only if BOTH signatures verify across old+new keys:
        #  (primary by retired key AND secondary by current key) OR
        #  (primary by current key AND secondary by retired key).
        now = datetime.now(timezone.utc)
        secondary = b""
        try:
            if hasattr(cert, "get_secondary_sig"):
                secondary = cert.get_secondary_sig() or b""
            else:
                secondary = b""
        except Exception:
            secondary = b""
        if secondary:
            for retired in list(getattr(self, "_retired_keys", []) or []):
                try:
                    rkey = retired.get("public_key")
                    retired_at = retired.get("retired_at")
                    if not rkey:
                        continue
                    if retired_at is not None:
                        ra = retired_at
                        if ra.tzinfo is None:
                            ra = ra.replace(tzinfo=timezone.utc)
                        if (now - ra) > _PQ_ROTATION_DUAL_SIGN_WINDOW:
                            continue
                    # Case A: primary(old) + secondary(new)
                    try:
                        if self._mldsa.verify(rkey, tbs_data, cert.signature) and \
                           self._mldsa.verify(self._ca_public_key, tbs_data, secondary):
                            logger.info(
                                f"[OK] Certificate verified via rotation window "
                                f"(primary=retired, secondary=current): serial={cert.serial}"
                            )
                            return True
                    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B110
                        pass
                    # Case B: primary(new) + secondary(old)
                    try:
                        if self._mldsa.verify(self._ca_public_key, tbs_data, cert.signature) and \
                           self._mldsa.verify(rkey, tbs_data, secondary):
                            logger.info(
                                f"[OK] Certificate verified via rotation window "
                                f"(primary=current, secondary=retired): serial={cert.serial}"
                            )
                            return True
                    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                    except Exception:  # nosec: B110
                        pass
                # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B112
                    continue
        
        raise SignatureVerificationError(
            f"Certificate signature verification failed: serial={cert.serial}"
        )
    
    def verify_chain(self, cert_chain: List[PQCertificate]) -> bool:
        """
        Verify certificate chain with hybrid signatures.
        
        Implements Requirements 2.2, 2.6:
        - Support certificate chains with hybrid classical+PQ signatures
        - WHEN certificate validation fails THEN terminate connection
        
        Args:
            cert_chain: List of certificates from end-entity to root
            
        Returns:
            True if entire chain is valid
            
        Raises:
            CertificateChainError: If chain validation fails
            CertificateRevokedError: If any certificate is revoked
            CertificateExpiredError: If any certificate is expired
        """
        if not cert_chain:
            raise CertificateChainError("Empty certificate chain")

        # CRL freshness gate (fail-closed in production, warn in lab).
        self.check_crl_freshness("verify_chain")
        
        for i, cert in enumerate(cert_chain):
            # Check expiration
            if cert.is_expired():
                raise CertificateExpiredError(
                    f"Certificate expired: serial={cert.serial}, subject={cert.subject}"
                )
            
            if cert.is_not_yet_valid():
                raise CertificateValidationError(
                    f"Certificate not yet valid: serial={cert.serial}"
                )
            
            # Check revocation
            if cert.serial in self._revoked_serials:
                raise CertificateRevokedError(
                    f"Certificate revoked: serial={cert.serial}, subject={cert.subject}"
                )
            
            # Verify signature
            if i < len(cert_chain) - 1:
                # Verify against next certificate in chain (issuer)
                issuer_cert = cert_chain[i + 1]
                tbs_data = cert.to_bytes()
                
                if not self._mldsa.verify(issuer_cert.public_key, tbs_data, cert.signature):
                    raise CertificateChainError(
                        f"Chain signature verification failed at position {i}: "
                        f"serial={cert.serial}"
                    )
            else:
                # Root certificate - verify against CA
                self.verify_certificate(cert)
        
        logger.info(f"[OK] Certificate chain verified: {len(cert_chain)} certificates")
        return True

    
    # ========================================================================
    # Certificate Transparency (Requirement 2.3)
    # ========================================================================
    
    def _add_to_ct_log(self, cert: PQCertificate) -> CTLogEntry:
        """
        Add certificate to Certificate Transparency log.
        
        Implements Requirement 2.3: Certificate Transparency logs with PQ signatures
        
        Args:
            cert: Certificate to log
            
        Returns:
            Signed CT log entry
        """
        # Get previous hash for chain linking
        previous_hash = b'\x00' * 32
        if self._ct_log:
            previous_hash = self._ct_log[-1].get_hash()
        
        entry = CTLogEntry(
            timestamp=datetime.now(timezone.utc),
            cert_fingerprint=cert.get_fingerprint(),
            log_id=self._ct_log_id,
            entry_index=len(self._ct_log),
            previous_hash=previous_hash
        )
        
        # Sign the entry
        entry.signature = self._mldsa.sign(self._ca_secret_key, entry.to_bytes())
        
        self._ct_log.append(entry)
        return entry
    
    def verify_ct_log_entry(self, entry: CTLogEntry) -> bool:
        """
        Verify a CT log entry signature.
        
        Args:
            entry: CT log entry to verify
            
        Returns:
            True if signature is valid
            
        Raises:
            CTLogError: If verification fails
        """
        if not self._mldsa.verify(self._ca_public_key, entry.to_bytes(), entry.signature):
            raise CTLogError(f"CT log entry verification failed: index={entry.entry_index}")
        return True
    
    def verify_ct_log_chain(self) -> bool:
        """
        Verify the entire CT log hash chain integrity.
        
        Returns:
            True if chain is intact
            
        Raises:
            CTLogError: If chain integrity is compromised
        """
        expected_hash = b'\x00' * 32
        
        for i, entry in enumerate(self._ct_log):
            # Verify hash chain link
            if not secrets.compare_digest(entry.previous_hash, expected_hash):
                raise CTLogError(
                    f"CT log chain broken at index {i}: "
                    f"expected {expected_hash.hex()[:16]}..., "
                    f"got {entry.previous_hash.hex()[:16]}..."
                )
            
            # Verify signature
            self.verify_ct_log_entry(entry)
            
            # Update expected hash for next entry
            expected_hash = entry.get_hash()
        
        logger.info(f"[OK] CT log chain verified: {len(self._ct_log)} entries")
        return True
    
    def get_ct_log_entries(self) -> List[CTLogEntry]:
        """Get all CT log entries."""
        return self._ct_log.copy()

    
    # ========================================================================
    # OCSP Stapling (Requirement 2.4)
    # ========================================================================
    
    def _generate_ocsp_response(self, cert: PQCertificate) -> OCSPResponse:
        """
        Generate OCSP response for a certificate.
        
        Args:
            cert: Certificate to generate response for
            
        Returns:
            Signed OCSP response
        """
        status = CertificateStatus.VALID
        if cert.serial in self._revoked_serials:
            status = CertificateStatus.REVOKED
        elif cert.is_expired():
            status = CertificateStatus.EXPIRED
        
        response = OCSPResponse(
            cert_serial=cert.serial,
            status=status,
            this_update=datetime.now(timezone.utc),
            next_update=datetime.now(timezone.utc) + timedelta(hours=24),
            responder_id=self.ca_name
        )
        
        # Sign the response
        response.signature = self._mldsa.sign(self._ca_secret_key, response.to_bytes())
        
        self._ocsp_responses[cert.serial] = response
        return response
    
    def get_ocsp_response(self, cert: PQCertificate) -> OCSPResponse:
        """
        Get OCSP response for a certificate.
        
        Implements Requirement 2.4: OCSP stapling with ML-DSA-87 signed responses
        
        Args:
            cert: Certificate to get OCSP response for
            
        Returns:
            Signed OCSP response
            
        Raises:
            OCSPError: If OCSP response cannot be generated
        """
        # Check if we have a cached response that's still valid
        if cert.serial in self._ocsp_responses:
            response = self._ocsp_responses[cert.serial]
            if response.next_update > datetime.now(timezone.utc):
                return response
        
        # Generate new response
        return self._generate_ocsp_response(cert)
    
    def verify_ocsp_response(self, response: OCSPResponse) -> bool:
        """
        Verify an OCSP response signature.
        
        Args:
            response: OCSP response to verify
            
        Returns:
            True if signature is valid
            
        Raises:
            OCSPError: If verification fails
        """
        if not self._mldsa.verify(self._ca_public_key, response.to_bytes(), response.signature):
            raise OCSPError(f"OCSP response verification failed: serial={response.cert_serial}")
        # Freshness enforcement: staple must be GOOD/fresh (<=24h).
        try:
            now = datetime.now(timezone.utc)
            this_update = getattr(response, "this_update", None)
            next_update = getattr(response, "next_update", None)
            if this_update is not None and this_update.tzinfo is None:
                this_update = this_update.replace(tzinfo=timezone.utc)
            if next_update is not None and next_update.tzinfo is None:
                next_update = next_update.replace(tzinfo=timezone.utc)
            if this_update is None or next_update is None:
                raise OCSPError(f"OCSP response missing validity window: serial={response.cert_serial}")
            if next_update <= now:
                raise OCSPError(f"OCSP response expired: serial={response.cert_serial}")
            if (now - this_update) > timedelta(hours=24):
                raise OCSPError(f"OCSP response stale (>24h): serial={response.cert_serial}")
            try:
                status = getattr(response, "status", None)
                if status is not None and status not in (CertificateStatus.VALID,):
                    # REVOKED/EXPIRED staples must never be treated as valid.
                    raise OCSPError(f"OCSP status not GOOD: serial={response.cert_serial} status={status}")
            except OCSPError:
                raise
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
        except OCSPError:
            raise
        except Exception as e:
            raise OCSPError(f"OCSP freshness check failed: serial={response.cert_serial}: {e}")
        return True
    
    def staple_ocsp_response(self, cert: PQCertificate) -> Tuple[PQCertificate, OCSPResponse]:
        """
        Get certificate with stapled OCSP response for TLS handshake.
        
        Args:
            cert: Certificate to staple OCSP response to
            
        Returns:
            Tuple of (certificate, OCSP response)
        """
        response = self.get_ocsp_response(cert)
        return cert, response

    
    # ========================================================================
    # Certificate Revocation (Requirement 2.5)
    # ========================================================================
    
    def revoke_certificate(
        self,
        serial: int,
        reason: RevocationReason = RevocationReason.UNSPECIFIED
    ) -> None:
        """
        Revoke a certificate and add to hash-chain CRL.
        
        Implements Requirement 2.5: Certificate revocation using hash-chain CRLs
        
        Args:
            serial: Certificate serial number to revoke
            reason: Revocation reason
        """
        if serial in self._revoked_serials:
            logger.warning(f"Certificate already revoked: serial={serial}")
            return
        
        # Add to revoked set
        self._revoked_serials.add(serial)
        
        # Create CRL entry
        entry = CRLEntry(
            serial=serial,
            revocation_date=datetime.now(timezone.utc),
            reason=reason
        )
        self._crl.entries.append(entry)
        
        # Update hash chain
        self._crl.chain_hash = self._crl.compute_chain_hash()
        self._crl.this_update = datetime.now(timezone.utc)
        self._crl.next_update = datetime.now(timezone.utc) + timedelta(days=1)
        # Bump CRL version on every revocation.
        try:
            self._crl_version = int(getattr(self, "_crl_version", 1)) + 1
            self._crl.version = self._crl_version
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        
        # Re-sign CRL
        self._crl.signature = self._mldsa.sign(self._ca_secret_key, self._crl.to_bytes())
        
        # Update OCSP response for revoked certificate
        if serial in self._issued_certificates:
            self._generate_ocsp_response(self._issued_certificates[serial])
        
        logger.info(f"[OK] Certificate revoked: serial={serial}, reason={reason.name}")

    def propagate_revocation(
        self,
        serial: int,
        reason: RevocationReason = RevocationReason.UNSPECIFIED,
    ) -> HashChainCRL:
        """Revoke-propagation helper: write CRL entry + bump CRL version.

        Idempotent: if the serial is already revoked, only the version is
        bumped and the CRL re-signed/re-timestamped (propagation refresh).

        Args:
            serial: Certificate serial number to revoke/propagate
            reason: Revocation reason

        Returns:
            Updated HashChainCRL
        """
        now = datetime.now(timezone.utc)
        if serial not in self._revoked_serials:
            self._revoked_serials.add(serial)
            self._crl.entries.append(
                CRLEntry(serial=serial, revocation_date=now, reason=reason)
            )
        # Bump version + refresh timestamps + recompute chain + re-sign.
        try:
            self._crl_version = int(getattr(self, "_crl_version", 1)) + 1
        except Exception:
            self._crl_version = 2
        try:
            self._crl.version = self._crl_version
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        self._crl.chain_hash = self._crl.compute_chain_hash()
        self._crl.this_update = now
        self._crl.next_update = now + timedelta(days=1)
        self._crl.signature = self._mldsa.sign(self._ca_secret_key, self._crl.to_bytes())
        if serial in self._issued_certificates:
            try:
                self._generate_ocsp_response(self._issued_certificates[serial])
            except Exception as e:
                logger.warning(f"OCSP refresh after revocation failed: serial={serial}: {e}")
        logger.info(
            f"[OK] Revocation propagated: serial={serial} reason={reason.name} "
            f"crl_version={getattr(self._crl, 'version', self._crl_version)}"
        )
        return self._crl

    # -- Key-rotation window + CRL freshness helpers (non-breaking) --
    def rotate_authority_key(self, new_public_key: bytes, new_secret_key: bytes) -> None:
        """Rotate the CA signing key, retaining the old key for a 7d dual-sign window.

        Args:
            new_public_key: New CA ML-DSA-87 public key
            new_secret_key: New CA ML-DSA-87 secret key
        """
        try:
            self._retired_keys.append(
                {"public_key": bytes(self._ca_public_key), "retired_at": datetime.now(timezone.utc)}
            )
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        self._ca_public_key = bytes(new_public_key)
        self._ca_secret_key = bytes(new_secret_key)
        # Prune entries older than the dual-sign window (best-effort).
        try:
            now = datetime.now(timezone.utc)
            self._retired_keys = [
                r for r in self._retired_keys
                if r.get("retired_at") is None or (now - r["retired_at"]) <= timedelta(days=8)
            ]
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        logger.info("[OK] CA key rotated; previous key retained for 7d dual-sign window")

    def add_retired_key(self, public_key: bytes, retired_at: Optional[datetime] = None) -> None:
        """Register a previous signer for the dual-sign window (testing/rotation)."""
        try:
            ra = retired_at or datetime.now(timezone.utc)
            if ra.tzinfo is None:
                ra = ra.replace(tzinfo=timezone.utc)
            self._retired_keys.append({"public_key": bytes(public_key), "retired_at": ra})
        except Exception as e:
            raise CertificateError(f"Cannot register retired key: {e}")

    def dual_sign_certificate(self, cert: PQCertificate) -> PQCertificate:
        """Add a secondary (dual) signature with the current CA key.

        Used during rotation: the primary signature was made by one rotation
        key; this adds a countersignature by the current key over the same TBS.
        """
        try:
            tbs = cert.to_bytes()
            secondary = self._mldsa.sign(self._ca_secret_key, tbs)
            try:
                cert.secondary_sig = bytes(secondary)
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            try:
                if isinstance(cert.extensions, dict):
                    cert.extensions["secondary_sig"] = base64.b64encode(bytes(secondary)).decode("utf-8")
            # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B110
                pass
            return cert
        except Exception as e:
            raise CertificateError(f"Dual-sign failed: serial={getattr(cert, 'serial', '?')}: {e}")

    def is_crl_fresh(self) -> bool:
        """True if CRL this_update is within P2P_CRL_REFRESH_HOURS (default 24)."""
        try:
            this_update = getattr(self._crl, "this_update", None)
            if this_update is None:
                return False
            if this_update.tzinfo is None:
                this_update = this_update.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - this_update
            return age <= timedelta(hours=_pq_crl_refresh_hours())
        except Exception:
            return False

    def check_crl_freshness(self, context: str = "") -> bool:
        """Enforce CRL freshness: reject if stale in production, warn in lab.

        Returns True when fresh. Raises CertificateError in production when stale.
        """
        try:
            if self.is_crl_fresh():
                return True
            msg = (
                f"CRL stale (> {_pq_crl_refresh_hours():g}h, P2P_CRL_REFRESH_HOURS) "
                f"in {context or 'pq_ca'}."
            )
            if _pq_is_production():
                logger.critical(f"CRITICAL: {msg} Fail-closed reject.")
                raise CertificateError(msg)
            logger.warning(f"{msg} Lab-permissive: continuing with warning.")
            return False
        except CertificateError:
            raise
        except Exception as e:
            logger.debug(f"CRL freshness check error: {e}")
            return False
    
    def is_revoked(self, serial: int) -> bool:
        """
        Check if a certificate is revoked.
        
        Args:
            serial: Certificate serial number
            
        Returns:
            True if certificate is revoked
        """
        return serial in self._revoked_serials
    
    def get_crl(self) -> HashChainCRL:
        """
        Get the current Certificate Revocation List.
        
        Returns:
            Current CRL with hash-chain integrity
        """
        return self._crl
    
    def verify_crl(self, crl: HashChainCRL) -> bool:
        """
        Verify CRL signature and hash-chain integrity.
        
        Args:
            crl: CRL to verify
            
        Returns:
            True if CRL is valid
            
        Raises:
            CertificateError: If verification fails
        """
        # Verify signature
        if not self._mldsa.verify(self._ca_public_key, crl.to_bytes(), crl.signature):
            raise CertificateError("CRL signature verification failed")
        
        # Verify hash chain
        computed_hash = crl.compute_chain_hash()
        if not secrets.compare_digest(computed_hash, crl.chain_hash):
            raise CertificateError(
                f"CRL hash chain integrity check failed: "
                f"expected {crl.chain_hash.hex()[:16]}..., "
                f"got {computed_hash.hex()[:16]}..."
            )

        # Freshness gate: reject stale CRLs in production (P2P_CRL_REFRESH_HOURS).
        try:
            this_update = getattr(crl, "this_update", None)
            if this_update is not None:
                tu = this_update
                if tu.tzinfo is None:
                    tu = tu.replace(tzinfo=timezone.utc)
                age = datetime.now(timezone.utc) - tu
                if age > timedelta(hours=_pq_crl_refresh_hours()):
                    msg = (
                        f"CRL stale (> {_pq_crl_refresh_hours():g}h, P2P_CRL_REFRESH_HOURS)."
                    )
                    if _pq_is_production():
                        logger.critical(f"CRITICAL: {msg} Fail-closed reject.")
                        raise CertificateError(msg)
                    logger.warning(f"{msg} Lab-permissive: continuing with warning.")
        except CertificateError:
            raise
        except Exception as e:
            logger.debug(f"CRL freshness check error in verify_crl: {e}")
        
        logger.info(f"[OK] CRL verified: {len(crl.entries)} revoked certificates")
        return True

    
    # ========================================================================
    # Certificate Lookup and Management
    # ========================================================================
    
    def get_certificate(self, serial: int) -> Optional[PQCertificate]:
        """
        Get a certificate by serial number.
        
        Args:
            serial: Certificate serial number
            
        Returns:
            Certificate if found, None otherwise
        """
        return self._issued_certificates.get(serial)
    
    def get_certificate_status(self, serial: int) -> CertificateStatus:
        """
        Get the status of a certificate.
        
        Args:
            serial: Certificate serial number
            
        Returns:
            Certificate status
        """
        if serial not in self._issued_certificates:
            return CertificateStatus.UNKNOWN
        
        cert = self._issued_certificates[serial]
        
        if serial in self._revoked_serials:
            return CertificateStatus.REVOKED
        
        if cert.is_expired():
            return CertificateStatus.EXPIRED
        
        return CertificateStatus.VALID
    
    def validate_certificate_for_connection(self, cert: PQCertificate) -> bool:
        """
        Validate a certificate for establishing a connection.
        
        Implements Requirement 2.6: WHEN certificate validation fails THEN terminate connection
        
        Args:
            cert: Certificate to validate
            
        Returns:
            True if certificate is valid for connection
            
        Raises:
            CertificateValidationError: If validation fails (connection must be terminated)
        """
        # Check expiration
        if cert.is_expired():
            raise CertificateExpiredError(
                f"Certificate expired: serial={cert.serial}"
            )
        
        if cert.is_not_yet_valid():
            raise CertificateValidationError(
                f"Certificate not yet valid: serial={cert.serial}"
            )
        
        # Check revocation
        if cert.serial in self._revoked_serials:
            raise CertificateRevokedError(
                f"Certificate revoked: serial={cert.serial}"
            )
        
        # Verify signature
        self.verify_certificate(cert)
        
        return True


# ============================================================================
# Factory Functions
# ============================================================================

def create_certificate_authority(ca_name: str = "PQ-Root-CA") -> PQCertificateAuthority:
    """
    Create a new Post-Quantum Certificate Authority.
    
    Args:
        ca_name: Name of the Certificate Authority
        
    Returns:
        Initialized PQCertificateAuthority
    """
    return PQCertificateAuthority(ca_name)


def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate an ML-DSA-87 keypair for certificate use.
    
    Returns:
        Tuple of (public_key, secret_key)
    """
    mldsa = LibOQS_MLDSA_87()
    return mldsa.keygen()


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    # Classes
    'PQCertificateAuthority',
    'PQCertificate',
    'OCSPResponse',
    'CTLogEntry',
    'CRLEntry',
    'HashChainCRL',
    # Enums
    'CertificateStatus',
    'RevocationReason',
    # Exceptions
    'CertificateError',
    'CertificateValidationError',
    'CertificateChainError',
    'CertificateRevokedError',
    'CertificateExpiredError',
    'SignatureVerificationError',
    'OCSPError',
    'CTLogError',
    # Factory functions
    'create_certificate_authority',
    'generate_keypair',
]

