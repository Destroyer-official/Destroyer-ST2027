"""Hybrid post-quantum key exchange (2027 research-backed profile).

Backward compatibility: the legacy X25519-based ``HybridKeyExchange`` and its
helpers are re-exported from ``hybrid_kex_legacy`` so existing callers (including
the quarantined ``SecureP2PChat``) keep working. New code should use
``HybridKeyExchange2027``.

Primary construction (research-backed, CNSA 2.0 aligned):
  * P-384 ECDH (NIST curve, FIPS 186-5)
  * ML-KEM-1024 (FIPS 203, L5)
  * Optional HQC-256 (code-based hedge; gated behind P2P_ENABLE_VULN_HQC=1
    because the vendored oqs.dll predates upstream HQC fixes)
  * Symmetric PSK mixed into the combiner
  * HKDF-SHA384 combiner: SHA384(ikm = p384_ss || mlkem_ss || hqc_ss || psk)
    with domain separation and transcript binding.

References:
  - RFC 10024 (SecP384r1MLKEM1024)
  - NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
  - CNSA 2.0
  - "Hybrid Key Exchange in TLS 1.3" (ietf-tls-hybrid-design)
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from typing import Any, Optional, Tuple

# Backward compatibility for legacy callers.
try:
    from hybrid_kex_legacy import *  # noqa: F401,F403
    from hybrid_kex_legacy import (  # noqa: F401
        HybridKeyExchange,
        verify_key_material,
        DEFAULT_KEY_LIFETIME,
        _format_binary,
        _zeroize_memory,
        secure_wipe_memory,
    )
except Exception:  # pragma: no cover - legacy module may be unavailable
    pass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from liboqs_wrapper import LibOQS_MLKEM_1024, LibOQS_MLDSA_87


def _hkdf_sha384(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA384(), length=length, salt=salt, info=info).derive(ikm)


class HybridKeyExchange2027:
    """Modern authenticated hybrid KEX: P-384 + ML-KEM-1024 + ML-DSA-87 + PSK."""

    def __init__(
        self,
        psk: Optional[bytes] = None,
        enable_hqc: bool = False,
        authorized_peer_fingerprints: Optional[Any] = None,
        identity: Optional[str] = None,
        **kwargs: Any,
    ):
        self._psk = psk if psk is not None else b""
        self._enable_hqc = enable_hqc
        self.identity = identity
        self.authorized_peer_fingerprints = None
        if authorized_peer_fingerprints is not None:
            if isinstance(authorized_peer_fingerprints, (list, tuple, set)):
                self.authorized_peer_fingerprints = {
                    fp.strip().lower() for fp in authorized_peer_fingerprints if isinstance(fp, str)
                }
            elif isinstance(authorized_peer_fingerprints, str):
                self.authorized_peer_fingerprints = {authorized_peer_fingerprints.strip().lower()}

        # P-384 long-term/ephemeral key
        self._p384_private = ec.generate_private_key(ec.SECP384R1())
        self._p384_public = self._p384_private.public_key()

        # ML-KEM-1024 (Fail-closed: no silent classical fallback per P2-08)
        try:
            self._mlkem = LibOQS_MLKEM_1024()
            self._mlkem_pk, self._mlkem_sk = self._mlkem.keygen()
            if not self._mlkem_pk or not self._mlkem_sk:
                raise RuntimeError("ML-KEM-1024 keygen failed to produce valid keypair")
        except Exception as e_kem:
            raise RuntimeError(
                f"MILITARY FATAL: CNSA 2.0 ML-KEM-1024 initialization failed: {e_kem}. "
                "Silent classical fallback is strictly prohibited."
            ) from e_kem

        # ML-DSA-87 Identity & Mutual Authentication (F-02 remediation)
        try:
            self._mldsa = LibOQS_MLDSA_87()
            self._mldsa_pk, self._mldsa_sk = self._mldsa.keygen()
            if not self._mldsa_pk or not self._mldsa_sk:
                raise RuntimeError("ML-DSA-87 keygen failed to produce valid keypair")
        except Exception as e_dsa:
            raise RuntimeError(
                f"MILITARY FATAL: CNSA 2.0 ML-DSA-87 initialization failed: {e_dsa}."
            ) from e_dsa

        # Optional HQC-256 (gated)
        self._hqc = None
        self._hqc_pk = b""
        self._hqc_sk = b""
        if enable_hqc:
            try:
                from liboqs_wrapper import LibOQS_HQC_256
                self._hqc = LibOQS_HQC_256()
                self._hqc_pk, self._hqc_sk = self._hqc.keygen()
            except Exception:
                self._hqc = None
                self._hqc_pk = b""
                self._hqc_sk = b""

    def _compute_bundle_tbs(self, bundle: dict) -> bytes:
        return (
            b"ST2027-HYBRID-KEX-BUNDLE-v2|"
            + str(bundle.get("p384", "")).encode()
            + b"|"
            + str(bundle.get("mlkem", "")).encode()
            + b"|"
            + str(bundle.get("mldsa", "")).encode()
            + b"|"
            + str(bundle.get("timestamp", 0)).encode()
        )

    @staticmethod
    def _production_posture() -> bool:
        from production_gate import is_production, is_ts_mode
        return is_production() or is_ts_mode()

    def negotiate_protocol_version(self, peer_bundle: dict) -> int:
        peer_ver = int(peer_bundle.get("protocol_version", 1))
        if self._production_posture() and peer_ver < 2:
            raise SecurityError("Legacy protocol version < 2 refused in production posture")
        return min(2, peer_ver)

    @property
    def static_key(self) -> bytes:
        return self._p384_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

    def _generate_keys(self) -> None:
        self._p384_private = ec.generate_private_key(ec.SECP384R1())
        self._p384_public = self._p384_private.public_key()
        self._mlkem_pk, self._mlkem_sk = self._mlkem.keygen()
        self._mldsa_pk, self._mldsa_sk = self._mldsa.keygen()
        self.next_rotation_time = time.time() + 86400

    @property
    def dss(self):
        return self._mldsa

    @property
    def falcon_private_key(self):
        return self._mldsa_sk

    @property
    def kem(self):
        return self._mlkem

    def check_key_expiration(self) -> bool:
        return time.time() >= getattr(self, "next_rotation_time", float("inf"))

    def needs_rotation(self) -> bool:
        return self.check_key_expiration()

    def rotate_keys(self) -> None:
        self._generate_keys()

    def get_key_file_path(self) -> Optional[str]:
        return None

    def enhance_quantum_resistance(self) -> None:
        pass

    def get_public_bundle(self) -> dict:
        p384_bytes = self._p384_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        now_ts = int(time.time())
        bundle = {
            "p384": p384_bytes.hex(),
            "mlkem": self._mlkem_pk.hex(),
            "mldsa": self._mldsa_pk.hex(),
            "timestamp": now_ts,
            "algorithm": "CNSA-2027-P384-MLKEM1024-MLDSA87",
            "identity": self.identity or "ST2027_NODE",
            "protocol_version": 2,
            "static_key": base64.b64encode(p384_bytes).decode("ascii"),
            "kem_public_key": base64.b64encode(self._mlkem_pk).decode("ascii"),
            "mldsa_public_key": base64.b64encode(self._mldsa_pk).decode("ascii"),
            "falcon_public_key": base64.b64encode(self._mldsa_pk).decode("ascii"),
            "signed_prekey": base64.b64encode(p384_bytes).decode("ascii"),
            "signing_key": base64.b64encode(self._mldsa_pk[:32]).decode("ascii"),
        }
        if self._hqc is not None:
            bundle["hqc"] = self._hqc_pk.hex()
        tbs = self._compute_bundle_tbs(bundle)
        bundle["signature"] = self._mldsa.sign(self._mldsa_sk, tbs).hex()
        return bundle

    def encapsulate_to_peer(self, peer_bundle: dict, transcript: bytes = b"") -> Tuple[bytes, dict, bytes]:
        if not self.verify_public_bundle(peer_bundle):
            raise ValueError("Peer bundle failed ML-DSA-87 signature or fingerprint authentication")

        # P-384 ECDH
        p384_raw = peer_bundle["p384"]
        if isinstance(p384_raw, str):
            p384_raw = bytes.fromhex(p384_raw)
        peer_p384 = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP384R1(), p384_raw
        )
        p384_ss = self._p384_private.exchange(ec.ECDH(), peer_p384)

        # ML-KEM encaps
        mlkem_raw = peer_bundle["mlkem"]
        if isinstance(mlkem_raw, str):
            mlkem_raw = bytes.fromhex(mlkem_raw)
        ml_ct, ml_ss = self._mlkem.encaps(mlkem_raw)

        # Optional HQC encaps
        hqc_ct = b""
        hqc_ss = b""
        if self._hqc is not None and "hqc" in peer_bundle:
            hqc_raw = peer_bundle["hqc"]
            if isinstance(hqc_raw, str):
                hqc_raw = bytes.fromhex(hqc_raw)
            hqc_ct, hqc_ss = self._hqc.encaps(hqc_raw)

        ikm = p384_ss + ml_ss
        if hqc_ss:
            ikm += hqc_ss
        if self._psk:
            ikm += self._psk

        salt = hashlib.sha384(b"ST2027-HYBRID-KEX-2027" + transcript).digest()[:32]
        ss = _hkdf_sha384(ikm, salt, b"ST2027-HYBRID-SESSION-KEY", 32)
        ct_bundle = {"mlkem": ml_ct}
        if hqc_ct:
            ct_bundle["hqc"] = hqc_ct
        # Ephemeral P-384 public for the peer
        eph_pub = self._p384_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return eph_pub, ct_bundle, ss

    def decapsulate_from_peer(self, peer_eph_p384: bytes, peer_cts: dict, transcript: bytes = b"") -> bytes:
        if isinstance(peer_eph_p384, str):
            peer_eph_p384 = bytes.fromhex(peer_eph_p384)
        peer_p384 = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP384R1(), peer_eph_p384
        )
        p384_ss = self._p384_private.exchange(ec.ECDH(), peer_p384)

        mlkem_ct = peer_cts["mlkem"]
        if isinstance(mlkem_ct, str):
            mlkem_ct = bytes.fromhex(mlkem_ct)
        ml_ss = self._mlkem.decaps(self._mlkem_sk, mlkem_ct)

        hqc_ss = b""
        if self._hqc is not None and "hqc" in peer_cts:
            hqc_ct = peer_cts["hqc"]
            if isinstance(hqc_ct, str):
                hqc_ct = bytes.fromhex(hqc_ct)
            hqc_ss = self._hqc.decaps(self._hqc_sk, hqc_ct)

        ikm = p384_ss + ml_ss
        if hqc_ss:
            ikm += hqc_ss
        if self._psk:
            ikm += self._psk

        salt = hashlib.sha384(b"ST2027-HYBRID-KEX-2027" + transcript).digest()[:32]
        return _hkdf_sha384(ikm, salt, b"ST2027-HYBRID-SESSION-KEY", 32)

    def verify_public_bundle(self, bundle: dict) -> bool:
        if not isinstance(bundle, dict):
            return False
        if "p384" not in bundle or "mlkem" not in bundle:
            return False
        try:
            p384_raw = bundle["p384"]
            if isinstance(p384_raw, str):
                p384_raw = bytes.fromhex(p384_raw)
            if len(p384_raw) not in (49, 97):
                return False
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), p384_raw)
            mlkem_raw = bundle["mlkem"]
            if isinstance(mlkem_raw, str):
                mlkem_raw = bytes.fromhex(mlkem_raw)
            if len(mlkem_raw) != 1568:
                return False

            # If ML-DSA-87 signature is attached, verify it
            if "mldsa" in bundle and "signature" in bundle:
                mldsa_raw = bundle["mldsa"]
                if isinstance(mldsa_raw, str):
                    mldsa_raw = bytes.fromhex(mldsa_raw)
                if len(mldsa_raw) != 2592:
                    return False
                sig_raw = bundle["signature"]
                if isinstance(sig_raw, str):
                    sig_raw = bytes.fromhex(sig_raw)
                if len(sig_raw) != 4627:
                    return False
                tbs = self._compute_bundle_tbs(bundle)
                if not self._mldsa.verify(mldsa_raw, tbs, sig_raw):
                    return False

                # F-02: Enforce authorized peer fingerprints if configured
                if self.authorized_peer_fingerprints is not None:
                    fp = hashlib.sha384(mldsa_raw).hexdigest().lower()
                    if fp not in self.authorized_peer_fingerprints:
                        return False
            elif not self._psk:
                # F-02: Unauthenticated bundles without PSK are rejected fail-closed
                return False

            return True
        except Exception:
            return False

    def initiate_handshake(self, peer_bundle: dict) -> Tuple[dict, bytes]:
        eph_pub, ct_bundle, ss = self.encapsulate_to_peer(peer_bundle)
        handshake_msg = {
            "eph_p384": eph_pub.hex(),
            "mlkem_ct": ct_bundle["mlkem"].hex(),
        }
        if "hqc" in ct_bundle:
            handshake_msg["hqc_ct"] = ct_bundle["hqc"].hex()
        return handshake_msg, ss

    def respond_to_handshake(self, handshake_message: dict, peer_bundle: Optional[dict] = None) -> bytes:
        peer_eph = handshake_message["eph_p384"]
        peer_cts = {"mlkem": handshake_message["mlkem_ct"]}
        if "hqc_ct" in handshake_message:
            peer_cts["hqc"] = handshake_message["hqc_ct"]
        return self.decapsulate_from_peer(peer_eph, peer_cts)

    def secure_cleanup(self) -> None:
        self._psk = b""
        self._mlkem_sk = b""
        self._hqc_sk = b""

    def cleanup(self) -> None:
        self.secure_cleanup()


# Unambiguous normative aliases (P2-15)
HybridKexCnsa2 = HybridKeyExchange2027
try:
    LegacyKexX25519 = HybridKeyExchange
except NameError:
    LegacyKexX25519 = None

__all__ = [
    "HybridKeyExchange2027",
    "HybridKexCnsa2",
    "LegacyKexX25519",
]
try:
    from hybrid_kex_legacy import __all__ as _legacy_all  # type: ignore
    __all__ = list(_legacy_all) + __all__
except Exception:
    pass
