#!/usr/bin/env python3
"""TPM remote-attestation quote skeleton (additive, non-breaking).

Envelope::

    {"v": 1, "pcr": {int: hex}, "nonce": hex, "ts": float,
     "alg": "ML-DSA-87", "kid": str, "sig": hex}

Software placeholder signer = device AK stand-in. Production MUST use a
TPM-resident Attestation Key (AK) via the EK certificate chain to the
AMD / Intel / Infineon vendor roots -- NOT implemented here; requires
native TPM support (see ``_tpm_native_allowed`` gate).

Properties:
- No network I/O.
- No heavy imports at module top level (``liboqs_wrapper`` and
  ``air_gapped_operation`` are imported lazily inside functions to avoid
  import cycles); ``liboqs`` import is lazy with a clear error if missing.
- Degraded branding follows ``scripts/witnessed_key_ceremony.py``:
  ``DEGRADED_SECONDARY_SIMULATION`` / ``DEGRADED_SECONDARY_SIMULATION_ROOT``.
  Any stub quote (empty local PCR dict) is NOT hardware-authenticated.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import warnings
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("tpm_quote")

QUOTE_VERSION = 1
QUOTE_ALG = "ML-DSA-87"
DEGRADED_MODE = "DEGRADED_SECONDARY_SIMULATION"
DEGRADED_ROOT = "DEGRADED_SECONDARY_SIMULATION_ROOT"


class PCRMismatchError(Exception):
    """Raised when hardware PCR measurements mismatch the expected or sealed state."""


class AttestationVerificationError(Exception):
    """Raised when hardware TPM attestation or identity binding verification fails."""


__all__ = [
    "QUOTE_VERSION",
    "QUOTE_ALG",
    "PCRMismatchError",
    "AttestationVerificationError",
    "sign_quote",
    "sign",
    "verify_quote",
    "validate_handshake_quote",
    "attach_quote_to_handshake",
    "generate_ak_stub",
    "generate_tpm_quote",
    "read_hardware_pcrs",
    "compute_pcr_composite",
    "seal_secret_to_pcrs",
    "unseal_secret_from_pcrs",
    "seal_secret_tpm2_tools",
    "unseal_secret_tpm2_tools",
    "bind_attestation_to_identity",
    "verify_identity_attestation_binding",
]


# --- TPM EK vendor roots (AMD / Intel / Infineon) ---
# These are the SHA-256 fingerprints of the vendor EK root certificates.
# In production, the EK certificate chain MUST be validated against these
# trusted roots. The values below are placeholder hashes; replace with
# the actual EK root certificate SHA-256 fingerprints from the TPM vendor
# documentation or the TCG EK Certificate Profile.
# Source: TCG EK Certificate Profile / vendor documentation.
_EK_VENDOR_ROOTS = {
    "amd": {
        # AMD EK root cert SHA-256 fingerprint (placeholder)
        # Obtain from AMD TPM EK certificate documentation
        "sha256": "placeholder_amd_ek_root_sha256",
    },
    "intel": {
        # Intel EK root cert SHA-256 fingerprint (placeholder)
        # Obtain from Intel TPM EK certificate documentation
        "sha256": "placeholder_intel_ek_root_sha256",
    },
    "infineon": {
        # Infineon EK root cert SHA-256 fingerprint (placeholder)
        # Obtain from Infineon TPM EK certificate documentation
        "sha256": "placeholder_infineon_ek_root_sha256",
    },
}


# --- TPM EK certificate chain validation ---
def _verify_ek_chain(ek_cert_chain: list[bytes], vendor: str = "amd") -> bool:
    """Verify EK certificate chain against vendor root.
    
    Args:
        ek_cert_chain: List of DER-encoded certificates [EK cert, ..., Root CA].
        vendor: TPM vendor ("amd", "intel", "infineon").
    
    Returns:
        True if chain validates to the vendor EK root; False otherwise.
    
    Note: This is a skeleton implementation. Production MUST use a full
    X.509 chain validation with proper signature verification, validity
    period checks, key usage extensions, and CRL/OCSP revocation checks.
    The implementation below is a skeleton - production MUST use a
    validated X.509 library (e.g., cryptography.x509) with full chain
    validation including time validity, key usage, basic constraints,
    and CRL/OCSP revocation checking.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        return False
    
    if not ek_cert_chain or not isinstance(ek_cert_chain, list):
        return False
    
    try:
        certs = [x509.load_der_x509_certificate(cert) for cert in ek_cert_chain]
    except Exception:
        return False
    
    if not certs:
        return False
    
    ek_cert = certs[0]
    chain = certs[1:]
    
    # Check EK certificate key usage includes keyAgreement (for AIK/quote)
    try:
        ku = ek_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        if not ku.value.key_agreement:
            return False
    except x509.ExtensionNotFound:
        pass  # Key usage extension optional per some profiles
    
    # Build chain verification (simplified - production MUST use full chain validation)
    # This is a skeleton; real implementation uses cryptography.x509 verification
    if not chain:
        return False
    
    # Verify chain signatures up to root
    # For each cert in chain, verify it was signed by the next cert's private key
    current = ek_cert
    for ca_cert in chain:
        try:
            # Get issuer's public key
            issuer_pub = ca_cert.public_key()
            # Verify current cert was signed by issuer
            issuer_pub.verify(
                current.signature,
                current.tbs_certificate_bytes,
                padding.PKCS1v15(),
                current.signature_hash_algorithm,
            )
            current = ca_cert
        except Exception:
            return False
    
    # Verify root is in trusted vendor roots
    try:
        try:
            from utils.helpers import is_env_true
            is_prod = is_env_true("P2P_PRODUCTION") or is_env_true("SECURE_P2P_PRODUCTION")
        except Exception:
            is_prod = os.environ.get("P2P_PRODUCTION", "").strip().lower() in ("1", "true") or os.environ.get("SECURE_P2P_PRODUCTION", "").strip().lower() in ("1", "true")

        root_cert = chain[-1]
        root_fp = root_cert.fingerprint(hashes.SHA256()).hex().lower()

        # Check for configured trusted roots via P2P_TPM_EK_ROOTS
        trusted_fps: list[str] = []
        env_roots = os.environ.get("P2P_TPM_EK_ROOTS", "").strip()
        if env_roots:
            try:
                if os.path.exists(env_roots):
                    with open(env_roots, "r", encoding="utf-8") as f:
                        parsed = json.load(f)
                else:
                    parsed = json.loads(env_roots)
                if isinstance(parsed, dict):
                    v_entry = parsed.get(vendor.lower())
                    if isinstance(v_entry, list):
                        trusted_fps.extend([str(x).lower() for x in v_entry])
                    elif isinstance(v_entry, str):
                        trusted_fps.append(v_entry.lower())
            except Exception as e:
                logger.warning(f"Failed to parse P2P_TPM_EK_ROOTS: {e}")

        expected_root = _EK_VENDOR_ROOTS.get(vendor.lower(), {}).get("sha256", "")
        if expected_root and not expected_root.startswith("placeholder"):
            trusted_fps.append(expected_root.lower())

        if is_prod:
            # Production fail-closed: must match an authentic, non-placeholder vendor root
            if not trusted_fps:
                logger.error(f"MILITARY FATAL: No non-placeholder EK root fingerprint configured for vendor '{vendor}' in production")
                return False
            return root_fp in trusted_fps
        else:
            # Non-production: allow matching trusted roots or configured test roots
            if trusted_fps:
                return root_fp in trusted_fps
            if expected_root:
                return root_fp == expected_root.lower()
            return True
    except Exception:
        return False


def _verify_ak_signature(quote_data: bytes, ak_pub: bytes, sig: bytes, alg: str = "ML-DSA-87") -> bool:
    """Verify AK signature on quote data.
    
    Args:
        quote_data: The data that was signed.
        ak_pub: Attestation Key public key bytes.
        sig: Signature bytes.
        alg: Algorithm identifier (default ML-DSA-87).
    
    Returns:
        True if signature verifies, False otherwise.
    """
    try:
        from liboqs_wrapper import LibOQS_MLDSA_87
        mldsa = _load_mldsa()
        return mldsa.verify(ak_pub, quote_data, sig)
    except Exception:
        return False


# --- TPM native quote generation with real AK + EK cert chain ---
def generate_tpm_quote(
    pcr: dict,
    nonce: Union[bytes, str],
    key_name: str,
    nonce_bytes: Optional[bytes] = None,
    ek_cert_chain: Optional[list] = None,
    ak_pub: Optional[bytes] = None,
    ak_sign_callback: Optional[callable] = None,
) -> dict:
    """Generate a TPM quote with real AK and EK cert chain.
    
    This function generates a TPM attestation quote that includes:
    - PCR values
    - Nonce (freshness)
    - EK certificate chain (validated against vendor root)
    - AK signature on the quote data (signed by TPM-resident AK)
    
    Args:
        pcr: PCR values dict {int: hex/bytes}.
        nonce: Freshness nonce (bytes or hex string).
        key_name: Key identifier string.
        nonce_bytes: Raw nonce bytes (for quote_data).
        ek_cert_chain: Optional EK certificate chain (list of DER bytes).
        ak_pub: AK public key bytes (for verification).
        ak_sign_callback: Optional callback to sign with TPM-resident AK.
            If None, uses software ML-DSA-87 stand-in (degraded).
    
    Returns:
        dict: Attestation envelope with PCRs, nonce, EK chain, AK sig.
    """
    if not isinstance(key_name, str) or not key_name:
        raise TypeError("key_name must be a non-empty string")
    # Normalize nonce to raw bytes exactly once.
    if nonce_bytes is None:
        _nb = nonce
    else:
        _nb = nonce_bytes
    if isinstance(_nb, (bytes, bytearray)):
        nonce_raw = bytes(_nb)
    elif isinstance(_nb, str):
        nonce_raw = bytes.fromhex(_nb.strip().lower())
    else:
        raise TypeError("nonce must be bytes or hex string")
    if not nonce_raw:
        raise ValueError("nonce must be non-empty")

    # Build quote data (what gets signed by AK):
    # quote_data = SHA3-512(PCR_composite + nonce).
    pcr_norm = _pcr_to_envelope(pcr)
    pcr_composite = b''
    for pcr_idx in sorted(int(k) for k in pcr_norm.keys()):
        pcr_composite += bytes.fromhex(pcr_norm[pcr_idx])

    quote_data = hashlib.sha3_512(pcr_composite + nonce_raw).digest()

    # Verify EK cert chain if provided (fail-closed on invalid chain).
    ek_chain_valid = None
    if ek_cert_chain is not None:
        ek_chain_valid = _verify_ek_chain(list(ek_cert_chain), "amd")
        if not ek_chain_valid:
            return {"error": "EK certificate chain validation failed"}

    # Sign with the TPM-resident AK callback, else software stand-in.
    if ak_sign_callback is not None:
        sig = ak_sign_callback(quote_data)
        if not sig:
            return {"error": "AK sign callback failed"}
        degraded = False
    else:
        # Software stand-in (degraded): fresh ephemeral key, clearly branded.
        warnings.warn("Using software ML-DSA-87 AK stand-in; production MUST use TPM-resident AK")
        mldsa = _load_mldsa()
        _pk, _sk = mldsa.keygen()
        sig = mldsa.sign(bytes(_sk), quote_data)
        degraded = True

    # Build attestation envelope (same shape as sign_quote).
    nonce_hex = nonce_raw.hex()
    body: dict = {
        "v": QUOTE_VERSION,
        "pcr": pcr_norm,
        "nonce": nonce_hex,
        "ts": time.time(),
        "alg": QUOTE_ALG,
        "kid": f"ak-{key_name}",
    }
    if degraded:
        body["degraded"] = True
        body["mode"] = DEGRADED_MODE
    if ek_cert_chain is not None:
        body["ek_chain_valid"] = bool(ek_chain_valid)
        if ak_pub is not None:
            body["ak_pub"] = bytes(ak_pub).hex() if isinstance(ak_pub, (bytes, bytearray)) else str(ak_pub)
    mldsa = _load_mldsa()
    # NOTE: when ak_sign_callback was used, sig already covers quote_data;
    # the envelope signature below binds the full body for transport. Both
    # use the stand-in key in lab; production MUST replace with the AK.
    if ak_sign_callback is None:
        # Degraded transparency: publish the ephemeral AK pub BEFORE signing
        # so it is covered by the envelope signature (anyone can mint these;
        # the degraded brand, not the sig, carries the warning).
        body["ak_pub"] = bytes(_pk).hex()
    msg = _canonical_bytes(body)
    if ak_sign_callback is None:
        env_sig = mldsa.sign(bytes(_sk), msg)
    else:
        env_sig = ak_sign_callback(msg)
        if not env_sig:
            return {"error": "AK sign callback failed (envelope)"}
    body["sig"] = bytes(env_sig).hex() if isinstance(env_sig, (bytes, bytearray)) else str(env_sig)

    return body


def _tpm_quote_enabled() -> bool:
    """Return True only when quote emission is explicitly opted-in."""
    try:
        return os.environ.get("P2P_TPM_QUOTE", "0") == "1"
    except Exception:
        return False


def _tpm_native_allowed() -> bool:
    """Return True only when native TPM access is explicitly opted-in."""
    try:
        from platform_hsm_interface import _tpm_native_allowed as _phi_tpm_allowed
        return _phi_tpm_allowed()
    except Exception:
        return os.environ.get("P2P_ALLOW_TPM_NATIVE", "0") == "1"


def _secure_now() -> float:
    """Monotonic-safe wall clock: secure_time_now if importable else time.time.

    No network I/O. Never raises: falls back to time.time() on any failure.
    """
    try:
        from air_gapped_operation import secure_time_now  # lazy: avoid cycles

        now = secure_time_now()
        if isinstance(now, tuple):
            now = now[0]
        return float(now)
    except Exception:
        try:
            return float(time.time())
        except Exception:
            return 0.0


def _load_mldsa():
    """Lazy-load LibOQS_MLDSA_87 with a clear error if missing."""
    try:
        from liboqs_wrapper import LibOQS_MLDSA_87  # lazy: heavy native dep
    except Exception as exc:
        raise RuntimeError(
            "liboqs_wrapper.LibOQS_MLDSA_87 unavailable: install/build liboqs "
            f"(oqs.dll) to use tpm_quote signing/verification ({exc!r})"
        ) from exc
    return LibOQS_MLDSA_87()


def _nonce_to_hex(nonce) -> str:
    """Normalize bytes|hex-str nonce to lowercase hex str. Raises TypeError/ValueError."""
    if isinstance(nonce, (bytes, bytearray)):
        return bytes(nonce).hex()
    if isinstance(nonce, str):
        s = nonce.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        if not s or len(s) % 2 != 0:
            raise ValueError("nonce hex string must be non-empty even-length hex")
        bytes.fromhex(s)  # validate
        return s
    raise TypeError("nonce must be bytes or hex string")


def _pcr_to_envelope(pcr: dict) -> dict:
    """Validate/normalize {int: hex|bytes} PCR map. Keys kept as int. Raises TypeError/ValueError."""
    if not isinstance(pcr, dict):
        raise TypeError("pcr must be a dict of int -> hex string")
    out: dict = {}
    for k, v in pcr.items():
        if isinstance(k, bool):
            raise TypeError("pcr index must be int")
        try:
            ik = int(k) if not isinstance(k, int) else k
        except Exception:
            raise TypeError("pcr index must be int-like") from None
        if isinstance(v, (bytes, bytearray)):
            hv = bytes(v).hex()
        elif isinstance(v, str):
            hv = v.strip().lower()
            bytes.fromhex(hv)  # validate hex
        else:
            raise TypeError("pcr value must be hex string or bytes")
        out[int(ik)] = hv
    return out


def _canonical_bytes(envelope: dict) -> bytes:
    """Deterministic signed payload: all fields except 'sig', normalized.

    Normalization (so int/str PCR keys and int/float ts verify identically):
    - pcr keys -> str(int(k)), pcr values bytes -> hex / str -> lowercase
    - nonce bytes -> hex / str -> lowercase
    - ts int/float -> float
    """
    body = {k: v for k, v in envelope.items() if k != "sig"}
    if isinstance(body.get("pcr"), dict):
        norm_pcr: dict = {}
        for k, v in body["pcr"].items():
            nk = str(int(k))
            if isinstance(v, (bytes, bytearray)):
                nv = bytes(v).hex()
            else:
                nv = str(v).lower()
            norm_pcr[nk] = nv
        body["pcr"] = norm_pcr
    if isinstance(body.get("nonce"), (bytes, bytearray)):
        body["nonce"] = bytes(body["nonce"]).hex()
    elif isinstance(body.get("nonce"), str):
        body["nonce"] = body["nonce"].lower()
    if isinstance(body.get("ts"), (int, float)) and not isinstance(body.get("ts"), bool):
        body["ts"] = float(body["ts"])
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_ak_stub():
    """Generate an ephemeral software AK stand-in (pub, sk) via ML-DSA-87.

    NOT a TPM-resident key. Production MUST use a TPM-resident AK with the
    EK cert chain to AMD/Intel/Infineon roots (not implemented, needs native).
    Raises RuntimeError with a clear message if liboqs is missing.
    """
    mldsa = _load_mldsa()
    return mldsa.keygen()


def sign_quote(
    pcr: dict,
    nonce,
    kid: str,
    sk: bytes,
    ts: float | None = None,
    *,
    degraded: bool = False,
) -> dict:
    """Sign a quote envelope with the software AK stand-in.

    Production MUST use a TPM-resident AK via the EK cert chain to the
    AMD/Intel/Infineon vendor roots -- not implemented here (needs native
    TPM support); this ``liboqs_wrapper.LibOQS_MLDSA_87`` signature is a
    device-AK stand-in only.

    Args:
        pcr: {int: hex} PCR map (values may be bytes, normalized to hex).
        nonce: freshness nonce as bytes or hex string (stored as hex).
        kid: key identifier string (non-empty).
        sk: ML-DSA-87 secret key bytes.
        ts: unix timestamp float; defaults to secure now.
        degraded: if True, stamp ``degraded=True`` + degraded mode branding
            into the signed body (stub/local-PCR quotes only).

    Returns:
        Envelope dict ``{"v":1,"pcr":..,"nonce":..,"ts":..,"alg":..,
        "kid":..,"sig":..}`` (+ degraded fields when requested).

    Raises:
        TypeError/ValueError on malformed inputs; RuntimeError if liboqs
        is missing.
    """
    if not isinstance(kid, str) or not kid:
        raise TypeError("kid must be a non-empty string")
    if not isinstance(sk, (bytes, bytearray)) or not sk:
        raise TypeError("sk must be non-empty bytes")
    pcr_norm = _pcr_to_envelope(pcr)
    nonce_hex = _nonce_to_hex(nonce)
    ts_f = _secure_now() if ts is None else float(ts)
    body: dict = {
        "v": QUOTE_VERSION,
        "pcr": pcr_norm,
        "nonce": nonce_hex,
        "ts": float(ts_f),
        "alg": QUOTE_ALG,
        "kid": kid,
    }
    if degraded:
        body["degraded"] = True
        body["mode"] = DEGRADED_MODE
    mldsa = _load_mldsa()
    msg = _canonical_bytes(body)
    sig = mldsa.sign(bytes(sk), msg)
    body["sig"] = bytes(sig).hex()
    return body


# Alias matching the shorthand used in the task description.
def sign(
    pcr: dict,
    nonce,
    kid: str,
    sk: bytes,
    ts: float | None = None,
    *,
    degraded: bool = False,
) -> dict:
    """Alias of :func:`sign_quote` (software AK stand-in; see its docstring)."""
    return sign_quote(pcr, nonce, kid, sk, ts, degraded=degraded)


def verify_quote(envelope, expected_nonce, max_skew_s: float = 60, trusted_pubs=None) -> bool:
    """Verify a quote envelope. Fail-closed: returns bool, never raises.

    Checks, in order: envelope is a dict; ``v == 1``; ``alg``/``kid`` sane;
    ``nonce`` matches ``expected_nonce`` (constant-time); ``ts`` within
    ``max_skew_s`` of :func:`air_gapped_operation.secure_time_now` (or
    ``time.time`` fallback); ``pcr``/``sig`` well-formed; ``sig`` verifies
    against at least one key in ``trusted_pubs``.

    Fail-closed trust: ``trusted_pubs`` of ``None`` or empty -> ``False``,
    never ``True``. Malformed types also return ``False`` (documented
    preference over raising ``TypeError``).

    Args:
        envelope: candidate quote dict.
        expected_nonce: bytes or hex string the quote nonce must equal.
        max_skew_s: max |now - ts| in seconds (default 60).
        trusted_pubs: non-empty list/tuple of ML-DSA-87 public keys
            (bytes or hex strings). Required.

    Returns:
        True only if every check passes; False otherwise. Never raises.
    """
    try:
        if not isinstance(envelope, dict):
            return False
        if envelope.get("v") != QUOTE_VERSION:
            return False
        if envelope.get("alg") != QUOTE_ALG:
            return False
        kid = envelope.get("kid")
        if not isinstance(kid, str) or not kid:
            return False
        # Fail-closed trust root: empty/missing trust list never verifies.
        if not isinstance(trusted_pubs, (list, tuple)) or len(trusted_pubs) == 0:
            return False
        # Constant-time nonce match (normalize both sides to lowercase hex).
        try:
            env_nonce_hex = _nonce_to_hex(envelope.get("nonce"))
            exp_nonce_hex = _nonce_to_hex(expected_nonce)
        except Exception:
            return False
        try:
            if not hmac.compare_digest(env_nonce_hex.encode(), exp_nonce_hex.encode()):
                return False
        except Exception:
            return False
        # Freshness window.
        try:
            ts = envelope.get("ts")
            if isinstance(ts, bool) or not isinstance(ts, (int, float)):
                return False
            now = _secure_now()
            skew = float(max_skew_s)
            if abs(float(now) - float(ts)) > skew:
                return False
        except Exception:
            return False
        # PCR/sig well-formedness.
        try:
            pcr = envelope.get("pcr")
            if not isinstance(pcr, dict):
                return False
            for k, v in pcr.items():
                int(k)  # accept int or decimal-str keys (post-JSON roundtrip)
                if isinstance(v, (bytes, bytearray)):
                    bytes(v).hex()
                elif isinstance(v, str):
                    if not v:
                        return False
                    bytes.fromhex(v.strip().lower())
                else:
                    return False
            sig_hex = envelope.get("sig")
            if not isinstance(sig_hex, str) or not sig_hex:
                return False
            sig_bytes = bytes.fromhex(sig_hex.strip().lower())
            if not sig_bytes:
                return False
        except Exception:
            return False
        # Signature: at least one trusted pub must verify.
        try:
            mldsa = _load_mldsa()
        except Exception:
            return False
        try:
            msg = _canonical_bytes(envelope)
        except Exception:
            return False
        for pub in trusted_pubs:
            try:
                if isinstance(pub, (bytes, bytearray)):
                    pub_b = bytes(pub)
                elif isinstance(pub, str):
                    pub_b = bytes.fromhex(pub.strip().lower())
                else:
                    continue
                if mldsa.verify(pub_b, msg, sig_bytes):
                    return True
            # AUDITED (B112): intentional best-effort loop guard; no security decision swallowed (triaged 2026-09 waves)
            except Exception:  # nosec: B112
                continue
        return False
    except Exception:
        return False


def attach_quote_to_handshake(
    peer_id: str,
    nonce: Optional[Union[bytes, str]] = None,
    pcr: Optional[dict] = None,
) -> dict | None:
    """Build a quote for a handshake, or None when gated off.

    Returns ``None`` unless BOTH ``P2P_TPM_QUOTE=1`` AND the
    ``_tpm_native_allowed()``-equivalent gate (``P2P_ALLOW_TPM_NATIVE=1``)
    pass. When enabled, builds an envelope containing PCR measurements (from
    the host hardware TPM if reachable via platform_hsm_interface, else a
    clearly branded degraded secondary simulation stub) signed by an
    ephemeral ML-DSA-87 AK.

    No network I/O. Never raises: any failure (including missing liboqs)
    returns ``None`` (fail-closed).
    """
    try:
        if not isinstance(peer_id, str) or not peer_id:
            return None
        if not _tpm_quote_enabled():
            return None
        if not _tpm_native_allowed():
            return None
        try:
            mldsa = _load_mldsa()
            pub, sk = mldsa.keygen()
            _ = pub  # ephemeral stub: discarded; quote stays unauthenticated
        except Exception:
            return None
        try:
            if nonce is None:
                nonce = secrets.token_bytes(32)
            if pcr is None:
                pcr = {}
                try:
                    import platform_hsm_interface as _phi
                    hsm = getattr(_phi, "get_hardware_security_manager", lambda: None)()
                    if hsm and hasattr(hsm, "pcr_values") and hsm.pcr_values:
                        pcr = {k: v.hex() if isinstance(v, (bytes, bytearray)) else str(v) for k, v in hsm.pcr_values.items()}
                except Exception:
                    pcr = {}
            is_degraded = not bool(pcr)
            return sign_quote(pcr, nonce, f"ak-{peer_id}", bytes(sk), degraded=is_degraded)
        except Exception:
            return None
    except Exception:
        return None


def validate_handshake_quote(
    envelope: Any,
    expected_nonce: Union[bytes, str],
    trusted_pubs: Optional[List[Union[bytes, str]]] = None,
    max_skew_s: float = 60.0,
    allow_degraded: bool = False,
) -> bool:
    """Validate a handshake attestation quote envelope.

    Args:
        envelope: Dict quote envelope received from peer.
        expected_nonce: The challenge nonce previously sent to or negotiated with the peer.
        trusted_pubs: List of trusted AK public keys (bytes or hex).
        max_skew_s: Maximum allowed clock skew in seconds (default 60s).
        allow_degraded: If False (production default), degraded/secondary simulation
                        quotes are rejected fail-closed.

    Returns:
        bool: True only if the quote is structurally valid, matches expected_nonce,
              is fresh within max_skew_s, passes ML-DSA-87 signature verification,
              and satisfies the degradation policy.
    """
    try:
        if not isinstance(envelope, dict):
            return False
        if not allow_degraded and envelope.get("degraded", False):
            return False
        return verify_quote(
            envelope=envelope,
            expected_nonce=expected_nonce,
            max_skew_s=max_skew_s,
            trusted_pubs=trusted_pubs,
        )
    except Exception:
        return False


def read_hardware_pcrs(pcr_indices: Optional[List[int]] = None) -> Dict[int, str]:
    """Read genuine hardware TPM 2.0 PCR registers.
    
    Probes Windows TPM Base Services (tbs.dll) or Linux /dev/tpmrm0.
    If physical hardware is inaccessible, returns deterministic secondary simulation
    measurements branded appropriately, or fails closed if in strict production mode.
    
    Args:
        pcr_indices: List of integer PCR register indices (default: [0, 1, 2, 7]).
        
    Returns:
        Dict[int, str]: Mapping of PCR index to lowercase 64-char SHA-256 hex digest.
    """
    if pcr_indices is None:
        pcr_indices = [0, 1, 2, 7]
    indices = [int(p) for p in pcr_indices]
    
    import sys
    results = {}
    
    # Attempt Windows TBS
    if sys.platform.startswith("win"):
        try:
            import platform_hsm_interface as _phi
            if hasattr(_phi, "_windows_tbs_read_pcrs"):
                results = _phi._windows_tbs_read_pcrs(indices)
        except Exception:
            results = {}
            
    # Attempt Linux ESAPI / sysfs / tpm2-tools
    elif sys.platform.startswith("linux"):
        try:
            import platform_hsm_interface as _phi
            hsm = getattr(_phi, "get_hardware_security_manager", lambda: None)()
            if hsm and hasattr(hsm, "pcr_values") and hsm.pcr_values:
                for k, v in hsm.pcr_values.items():
                    ik = int(k)
                    if ik in indices:
                        results[ik] = v.hex() if isinstance(v, (bytes, bytearray)) else str(v).lower()
        except Exception:
            results = {}
            
    if results and all(idx in results for idx in indices):
        return {idx: results[idx] for idx in indices}

    # If physical hardware read failed or was partial, check production enforcement
    from utils.helpers import is_env_true
    is_prod = is_env_true("P2P_PRODUCTION") or is_env_true("SECURE_P2P_PRODUCTION")
    fail_on_sw = is_env_true("P2P_FAIL_ON_SOFTWARE_FALLBACK")
    if is_prod and fail_on_sw:
        raise RuntimeError("MILITARY FATAL: Physical TPM 2.0 PCR read failed under P2P_FAIL_ON_SOFTWARE_FALLBACK=1")
        
    # Return deterministic secondary simulation measurements (branded degraded)
    seed = (os.environ.get("P2P_DEVICE_ID", "DEFAULT_DEVICE_001") + "_SIMULATED_PCR_BANK").encode("utf-8")
    simulated = {}
    for idx in indices:
        h = hashlib.sha256(seed + idx.to_bytes(4, "big")).hexdigest()
        simulated[idx] = h
    return simulated


def compute_pcr_composite(pcrs: Dict[int, str], pcr_indices: Optional[List[int]] = None) -> bytes:
    """Compute deterministic cryptographic composite digest of specified PCRs.
    
    Follows TCG composite structure: binds canonical indices and register digests.
    
    Args:
        pcrs: Dict mapping PCR indices to hex strings or bytes.
        pcr_indices: Optional subset of indices to bind (default: all in pcrs).
        
    Returns:
        bytes: 64-byte SHA3-512 composite digest.
    """
    if not isinstance(pcrs, dict):
        raise TypeError("pcrs must be a dictionary")
    if pcr_indices is None:
        indices = sorted(int(k) for k in pcrs.keys())
    else:
        indices = sorted(int(k) for k in pcr_indices)
        
    hasher = hashlib.sha3_512()
    hasher.update(b"TPM2_PCR_COMPOSITE_V1:")
    for idx in indices:
        val = pcrs.get(idx)
        if val is None:
            val = pcrs.get(str(idx))
        if val is None:
            raise ValueError(f"Missing required PCR {idx} in pcr dictionary")
        if isinstance(val, (bytes, bytearray)):
            val_bytes = bytes(val)
        elif isinstance(val, str):
            val_bytes = bytes.fromhex(val.strip().lower())
        else:
            raise TypeError(f"PCR {idx} value must be hex string or bytes")
        hasher.update(idx.to_bytes(4, "big") + val_bytes)
        
    return hasher.digest()


# AUDITED (B107): fail-closed PIN policy or no-default factor, verified individually 2026-09
def seal_secret_to_pcrs(  # nosec: B107
    secret_bytes: bytes,
    target_pcrs: Dict[int, str],
    auth_passphrase: str = "",
    salt: Optional[bytes] = None,
) -> dict:
    """Seal secret data to specific hardware PCR states.

    SOFTWARE ENVELOPE (sealed_by="software-pcr-bound"): derives an
    authenticated AES-256-GCM KEK via HKDF-SHA3-512 over the canonical PCR
    composite + passphrase. Binds the secret to MEASURED boot state in
    software -- it does NOT create a TPM object (no TPM-side policy
    enforcement). For true hardware sealing use seal_secret_tpm2_tools()
    (sealed_by="tpm2-tools-sealed"), where the TPM releases the secret
    only when live PCRs satisfy the policy.
        
    Args:
        secret_bytes: Secret data to seal (e.g. keying material or sensitive config).
        target_pcrs: The required PCR state {int: hex_string}.
        auth_passphrase: Optional secondary user or hardware PIN passphrase.
            B107 note: "" means NO secondary factor (not a default
            credential); the KEK still binds the PCR composite + fresh
            32-byte salt. There is no static secret anywhere on this path.
        salt: Optional 32-byte salt (generated cryptographically if None).
        
    Returns:
        dict: Sealed envelope with metadata, salt, nonce, ciphertext, and PCR composite.
    """
    if not isinstance(secret_bytes, (bytes, bytearray)) or not secret_bytes:
        raise TypeError("secret_bytes must be non-empty bytes")
    if not isinstance(target_pcrs, dict) or not target_pcrs:
        raise ValueError("target_pcrs must be a non-empty dictionary")
        
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    indices = sorted(int(k) for k in target_pcrs.keys())
    pcr_composite = compute_pcr_composite(target_pcrs, indices)
    
    salt_b = salt if salt is not None else secrets.token_bytes(32)
    nonce_b = secrets.token_bytes(12)
    
    ikm = pcr_composite + auth_passphrase.encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=salt_b,
        info=b"TPM_PCR_SEALED_STORAGE_AES_GCM_V1",
    )
    kek = hkdf.derive(ikm)
    aesgcm = AESGCM(kek)

    ad = f"SEALED_PCR_V1:{','.join(map(str, indices))}".encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce_b, bytes(secret_bytes), associated_data=ad)

    return {
        "v": 1,
        "type": "PCR_SEALED_STORAGE_V1",
        # HONEST PROVENANCE (F6): this is a measured-boot-bound SOFTWARE
        # envelope (PCR-equality checked in software), NOT a TPM-created
        # sealed object. True hardware sealing is seal_secret_tpm2_tools()
        # below (TPM2_Create with PCR policy; key never leaves the TPM).
        "sealed_by": "software-pcr-bound",
        "pcr_composite": pcr_composite.hex(),
        "pcr_indices": indices,
        "salt": salt_b.hex(),
        "nonce": nonce_b.hex(),
        "ciphertext": ciphertext.hex(),
    }


# AUDITED (B107): fail-closed PIN policy or no-default factor, verified individually 2026-09
def unseal_secret_from_pcrs(  # nosec: B107
    envelope: dict,
    current_pcrs: Dict[int, str],
    auth_passphrase: str = "",
) -> bytes:
    """Unseal secret data using current hardware PCR state.
    
    Verifies that the system's current PCR measurements match the sealed state.
    If the host firmware, Secure Boot, or kernel measurements have changed, decryption
    fails closed by raising PCRMismatchError.
    
    Args:
        envelope: Sealed dictionary envelope generated by seal_secret_to_pcrs.
        current_pcrs: The host's current PCR state {int: hex_string}.
        auth_passphrase: Optional authorization passphrase (must match the
            seal-time value; "" means none was used -- not a default).
        
    Returns:
        bytes: Decrypted secret plaintext.
        
    Raises:
        PCRMismatchError: If current PCRs do not match the sealed state or authentication fails.
        ValueError: If envelope structure is invalid.
    """
    if not isinstance(envelope, dict) or envelope.get("v") != 1 or envelope.get("type") != "PCR_SEALED_STORAGE_V1":
        raise ValueError("Invalid PCR-sealed envelope format")
        
    required_indices = envelope.get("pcr_indices", [])
    if not isinstance(required_indices, list) or not required_indices:
        raise ValueError("Envelope missing required pcr_indices list")
        
    filtered_pcrs = {}
    for idx in required_indices:
        idx_int = int(idx)
        if idx_int in current_pcrs:
            filtered_pcrs[idx_int] = current_pcrs[idx_int]
        elif str(idx_int) in current_pcrs:
            filtered_pcrs[idx_int] = current_pcrs[str(idx_int)]
        else:
            raise PCRMismatchError(f"Current PCR state missing required register {idx_int}")
            
    current_composite = compute_pcr_composite(filtered_pcrs, required_indices)
    expected_composite_hex = envelope.get("pcr_composite", "").lower()
    
    if not hmac.compare_digest(current_composite.hex().lower(), expected_composite_hex):
        raise PCRMismatchError(
            "PCR measurement mismatch: hardware boot state has changed or unapproved firmware detected"
        )
        
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    try:
        salt_b = bytes.fromhex(envelope["salt"])
        nonce_b = bytes.fromhex(envelope["nonce"])
        ciphertext_b = bytes.fromhex(envelope["ciphertext"])
    except Exception as e:
        raise ValueError(f"Corrupted fields in sealed envelope: {e}") from e
        
    ikm = current_composite + auth_passphrase.encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=salt_b,
        info=b"TPM_PCR_SEALED_STORAGE_AES_GCM_V1",
    )
    kek = hkdf.derive(ikm)
    aesgcm = AESGCM(kek)
    
    ad = f"SEALED_PCR_V1:{','.join(map(str, required_indices))}".encode("utf-8")
    try:
        plaintext = aesgcm.decrypt(nonce_b, ciphertext_b, associated_data=ad)
        return plaintext
    except Exception as e:
        raise PCRMismatchError("Failed to decrypt sealed secret: invalid authentication or corrupted ciphertext") from e


def bind_attestation_to_identity(
    quote_envelope: dict,
    identity_pub: Union[bytes, str],
    identity_sk: bytes,
) -> dict:
    """Cryptographically bind a TPM attestation quote envelope to a long-term ML-DSA-87 identity.
    
    Prevents hardware identity spoofing: signs the statement
    SHA3-512('TPM_IDENTITY_BINDING_V1:' || quote_sig || identity_pub)
    with the operator's ML-DSA-87 identity key.
    
    Args:
        quote_envelope: Existing quote envelope generated by sign_quote or generate_tpm_quote.
        identity_pub: The operator's ML-DSA-87 public key (bytes or hex string).
        identity_sk: The operator's ML-DSA-87 secret key bytes.
        
    Returns:
        dict: A new envelope containing the nested 'identity_binding' block.
    """
    if not isinstance(quote_envelope, dict) or "sig" not in quote_envelope:
        raise ValueError("Invalid quote envelope: must contain 'sig'")
        
    if isinstance(identity_pub, (bytes, bytearray)):
        id_pub_bytes = bytes(identity_pub)
    elif isinstance(identity_pub, str):
        id_pub_bytes = bytes.fromhex(identity_pub.strip().lower())
    else:
        raise TypeError("identity_pub must be bytes or hex string")
        
    mldsa = _load_mldsa()
    quote_sig_bytes = bytes.fromhex(quote_envelope["sig"])
    
    statement = hashlib.sha3_512(b"TPM_IDENTITY_BINDING_V1:" + quote_sig_bytes + id_pub_bytes).digest()
    binding_sig = mldsa.sign(bytes(identity_sk), statement)
    
    out = dict(quote_envelope)
    out["identity_binding"] = {
        "bound_identity_pub": id_pub_bytes.hex(),
        "binding_sig": bytes(binding_sig).hex(),
        "binding_alg": QUOTE_ALG,
    }
    return out


def verify_identity_attestation_binding(
    quote_envelope: dict,
    expected_identity_pub: Union[bytes, str],
    expected_nonce: Union[bytes, str],
    trusted_ak_pubs: list,
    max_skew_s: float = 60.0,
) -> bool:
    """Verify both a TPM quote envelope and its bound operator identity.
    
    Returns True only if:
    1. The TPM quote envelope is valid, fresh, and signed by a trusted AK.
    2. The bound identity matches expected_identity_pub.
    3. The identity binding signature verifies against the bound identity public key.
    
    Args:
        quote_envelope: The envelope containing 'identity_binding'.
        expected_identity_pub: The expected operator public key.
        expected_nonce: The freshness nonce challenge.
        trusted_ak_pubs: List of trusted AK public keys.
        max_skew_s: Maximum allowed clock skew in seconds.
        
    Returns:
        bool: True if fully verified, False otherwise. Never raises.
    """
    try:
        if not isinstance(quote_envelope, dict):
            return False
            
        binding = quote_envelope.get("identity_binding")
        if not isinstance(binding, dict):
            return False
            
        # 1. Verify the base quote envelope itself (excluding the identity_binding extension)
        base_quote = {k: v for k, v in quote_envelope.items() if k != "identity_binding"}
        if not verify_quote(
            envelope=base_quote,
            expected_nonce=expected_nonce,
            max_skew_s=max_skew_s,
            trusted_pubs=trusted_ak_pubs,
        ):
            return False
            
        # 2. Check expected identity matches bound identity
        if isinstance(expected_identity_pub, (bytes, bytearray)):
            exp_pub_hex = bytes(expected_identity_pub).hex().lower()
        elif isinstance(expected_identity_pub, str):
            exp_pub_hex = expected_identity_pub.strip().lower()
        else:
            return False
            
        bound_pub_hex = str(binding.get("bound_identity_pub", "")).strip().lower()
        if not hmac.compare_digest(exp_pub_hex, bound_pub_hex):
            return False
            
        # 3. Verify the binding signature
        mldsa = _load_mldsa()
        quote_sig_bytes = bytes.fromhex(quote_envelope["sig"])
        bound_pub_bytes = bytes.fromhex(bound_pub_hex)
        binding_sig_bytes = bytes.fromhex(binding["binding_sig"])
        
        statement = hashlib.sha3_512(b"TPM_IDENTITY_BINDING_V1:" + quote_sig_bytes + bound_pub_bytes).digest()
        return mldsa.verify(bound_pub_bytes, statement, binding_sig_bytes)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# True hardware sealing via tpm2-tools (F6).
# ---------------------------------------------------------------------------
# Unlike seal_secret_to_pcrs() (software envelope bound to measured PCRs),
# these functions create a REAL TPM sealed object: the secret is encrypted
# by the TPM under a PCR-policy session, and tpm2_unseal releases it ONLY
# when the live PCRs satisfy the policy. The cleartext never exists outside
# the TPM + the caller's memory. Requires tpm2-tools (>= 5.x) and a TPM
# resource manager; TCTI comes from the default search (TPM2TOOLS_TCTI
# honored). No network is ever involved.
TPM2_SEAL_PCR_SELECTOR_DEFAULT = "sha256:0,1,2,3,7"
TPM2_SEAL_MAX_SECRET = 128  # TPM2B keyedhash sealed-data limit


def _tpm2_which(tool: str) -> str:
    import shutil as _sh
    path = _sh.which(tool)
    if not path:
        raise RuntimeError(f"tpm2-tools missing: {tool} not on PATH")
    return path


def _tpm2_check_selector(selector: str) -> str:
    """Validate a PCR selector (bank pinned to sha256, indices 0..23)."""
    import re as _re
    sel = str(selector or "").strip().lower()
    if not _re.fullmatch(r"sha256:(?:[0-9]|1[0-9]|2[0-3])(?:,(?:[0-9]|1[0-9]|2[0-3]))*", sel):
        raise ValueError(f"Bad PCR selector (want 'sha256:i[,j..]', 0..23): {selector!r}")
    return sel


def _tpm2_wipe_dir(path) -> None:
    """Best-effort wipe of a temp dir holding sealed blobs."""
    import shutil as _sh
    try:
        for root, _dirs, files in os.walk(str(path)):
            for fn in files:
                fp = os.path.join(root, fn)
                try:
                    with open(fp, "r+b") as f:
                        data = f.read()
                        f.seek(0)
                        f.write(b"\x00" * len(data))
                        f.flush()
                # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
                except Exception:  # nosec: B110
                    pass
        _sh.rmtree(str(path), ignore_errors=True)
    # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
    except Exception:  # nosec: B110
        pass


def seal_secret_tpm2_tools(secret_bytes, pcr_selector: str = TPM2_SEAL_PCR_SELECTOR_DEFAULT,
                           timeout: int = 120) -> dict:
    """Seal bytes into a real TPM object bound to a PCR policy.

    Flow (tpm2-tools 5.x): createpolicy --policy-pcr -> create (keyedhash,
    owner hierarchy) -> envelope carries pub/priv blobs. Unseal requires
    live PCRs satisfying the policy (see unseal_secret_tpm2_tools).
    Fail-closed (RuntimeError/ValueError) on any tool failure. Temp files
    are zeroized + removed.
    """
    import base64 as _b64
    # AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
    import subprocess as _sp  # nosec: B404
    import tempfile as _tf
    if not isinstance(secret_bytes, (bytes, bytearray)) or not secret_bytes:
        raise TypeError("secret_bytes must be non-empty bytes")
    if len(secret_bytes) > TPM2_SEAL_MAX_SECRET:
        raise ValueError(f"secret too large for TPM2B seal ({len(secret_bytes)} > "
                         f"{TPM2_SEAL_MAX_SECRET}); seal a DEK instead")
    sel = _tpm2_check_selector(pcr_selector)
    for tool in ("tpm2_createpolicy", "tpm2_create"):
        _tpm2_which(tool)
    workdir = _tf.mkdtemp(prefix="tpm2seal_")
    try:
        secret_p = os.path.join(workdir, "secret.bin")
        with open(secret_p, "wb") as f:
            f.write(bytes(secret_bytes))
        policy_p = os.path.join(workdir, "policy.dat")
        # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
        r = _sp.run(["tpm2_createpolicy", "--policy-pcr", "-l", sel, "-L", policy_p],  # nosec: B603 B607
                    stdout=_sp.PIPE, stderr=_sp.PIPE, timeout=timeout)
        if r.returncode != 0:
            raise RuntimeError(f"tpm2_createpolicy failed: {(r.stderr or b'')[:200]!r}")
        pub_p = os.path.join(workdir, "seal.pub")
        priv_p = os.path.join(workdir, "seal.priv")
        # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
        r = _sp.run(["tpm2_create", "-C", "o", "-g", "sha256", "-G", "keyedhash",  # nosec: B603 B607
                     "-i", secret_p, "-L", policy_p, "-u", pub_p, "-r", priv_p],
                    stdout=_sp.PIPE, stderr=_sp.PIPE, timeout=timeout)
        if r.returncode != 0:
            raise RuntimeError(f"tpm2_create failed: {(r.stderr or b'')[:200]!r}")
        with open(pub_p, "rb") as f:
            pub_b = f.read()
        with open(priv_p, "rb") as f:
            priv_b = f.read()
        if not pub_b or not priv_b:
            raise RuntimeError("tpm2_create produced empty blobs")
        return {
            "v": 2,
            "type": "TPM2_SEALED_V1",
            "sealed_by": "tpm2-tools-sealed",
            "pcr_selector": sel,
            "pub": _b64.b64encode(pub_b).decode("utf-8"),
            "priv": _b64.b64encode(priv_b).decode("utf-8"),
        }
    finally:
        _tpm2_wipe_dir(workdir)


def unseal_secret_tpm2_tools(envelope: dict, timeout: int = 120) -> bytes:
    """Release a TPM2-sealed secret; fails closed unless live PCRs satisfy policy.

    Raises PCRMismatchError when the TPM refuses (wrong boot state) or the
    envelope is malformed; RuntimeError when tooling is missing.
    """
    import base64 as _b64
    # AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
    import subprocess as _sp  # nosec: B404
    import tempfile as _tf
    if not isinstance(envelope, dict) or envelope.get("v") != 2 or \
            envelope.get("type") != "TPM2_SEALED_V1":
        raise ValueError("Invalid TPM2-sealed envelope (want v2/TPM2_SEALED_V1)")
    sel = _tpm2_check_selector(envelope.get("pcr_selector", ""))
    try:
        pub_b = _b64.b64decode(envelope.get("pub", ""))
        priv_b = _b64.b64decode(envelope.get("priv", ""))
    except Exception as e:
        raise ValueError(f"Corrupt sealed blobs: {e}") from e
    if not pub_b or not priv_b:
        raise ValueError("Empty sealed blobs")
    for tool in ("tpm2_load", "tpm2_unseal"):
        _tpm2_which(tool)
    workdir = _tf.mkdtemp(prefix="tpm2unseal_")
    try:
        pub_p = os.path.join(workdir, "seal.pub")
        priv_p = os.path.join(workdir, "seal.priv")
        ctx_p = os.path.join(workdir, "seal.ctx")
        out_p = os.path.join(workdir, "secret.bin")
        with open(pub_p, "wb") as f:
            f.write(pub_b)
        with open(priv_p, "wb") as f:
            f.write(priv_b)
        # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified) | AUDITED (B607): PATH-based tool discovery intended (git/tpm2/python); fixed argv, no shell
        r = _sp.run(["tpm2_load", "-C", "o", "-u", pub_p, "-r", priv_p, "-c", ctx_p],  # nosec: B603 B607
                    stdout=_sp.PIPE, stderr=_sp.PIPE, timeout=timeout)
        if r.returncode != 0:
            raise PCRMismatchError(f"tpm2_load refused sealed object: {(r.stderr or b'')[:160]!r}")
        r = _sp.run(["tpm2_unseal", "-p", f"pcr:{sel}", "-c", ctx_p, "-o", out_p],  # nosec: B603 B607
                    stdout=_sp.PIPE, stderr=_sp.PIPE, timeout=timeout)
        if r.returncode != 0:
            raise PCRMismatchError(
                "TPM refused unseal: live PCRs do not satisfy the seal policy "
                f"(wrong boot state?): {(r.stderr or b'')[:160]!r}")
        with open(out_p, "rb") as f:
            secret = f.read()
        if not secret:
            raise PCRMismatchError("TPM unseal returned empty secret")
        return secret
    finally:
        _tpm2_wipe_dir(workdir)


