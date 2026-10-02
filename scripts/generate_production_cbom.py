#!/usr/bin/env python3
"""
Generate Official Cryptographic Bill of Materials (CBOM)
=========================================================
Standard: CycloneDX v1.6 / v1.7 Specification with native Cryptographic Assets
Purpose: Provides complete cryptographic transparency evidence supporting
         NSA CNSA 2.0 (2027 gate) readiness, NIST FIPS 140-3 CAVP
         self-testing, and CSfC authorization PACKAGE PREPARATION
         (evidence for audits -- not an authorization).

Generates:
  compliance_reports/cyclonedx_cbom.json
  compliance_reports/cyclonedx_cbom.json.mldsa87.sig
  compliance_reports/cyclonedx_cbom.json.mldsa87.pub
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, List

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from liboqs_wrapper import LibOQS_MLDSA_87


def generate_cbom_data() -> dict:
    """Build standardized CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)."""
    serial_number = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    crypto_components = [
        # --- Post-Quantum Key Encapsulation (FIPS 203) ---
        {
            "type": "cryptographic-asset",
            "name": "ML-KEM-1024",
            "version": "FIPS 203 (Final 2024)",
            "description": "Primary Module Lattice Key Encapsulation Mechanism (NIST Level 5, 256-bit PQ security)",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "kem",
                    "parameterSetIdentifier": "ml-kem-1024",
                    "nistQuantumSecurityLevel": 5,
                    "classicalSecurityLevel": 256,
                    "quantumSecurity": "quantum-safe",
                    "standards": ["FIPS 203", "NSA CNSA 2.0", "NIST SP 800-227"],
                    "keyLength": 1568,
                    "secretKeyLength": 3168,
                    "ciphertextLength": 1568,
                    "sharedSecretLength": 32,
                    "implementation": "LibOQS native C assembly (liboqs 0.12.0+)",
                }
            }
        },
        {
            "type": "cryptographic-asset",
            "name": "Classic-McEliece-8192128f",
            "version": "NIST Round 4 / Conservative Code-Based",
            "description": "Secondary Conservative KEM for Hybrid Diversity (unbroken since 1978, Goppa codes)",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "kem",
                    "parameterSetIdentifier": "classic-mceliece-8192128f",
                    "nistQuantumSecurityLevel": 5,
                    "classicalSecurityLevel": 256,
                    "quantumSecurity": "quantum-safe",
                    "standards": ["NIST Round 4", "CNSA 2.0 Hybrid Diversity"],
                    "keyLength": 1357824,
                    "secretKeyLength": 14120,
                    "ciphertextLength": 208,
                    "sharedSecretLength": 32,
                    "implementation": "LibOQS native C",
                }
            }
        },
        # --- Post-Quantum Digital Signatures (FIPS 204 & FIPS 205) ---
        {
            "type": "cryptographic-asset",
            "name": "ML-DSA-87",
            "version": "FIPS 204 (Final 2024)",
            "description": "Primary Module Lattice Digital Signature Algorithm (NIST Level 5, 256-bit PQ security)",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "signature",
                    "parameterSetIdentifier": "ml-dsa-87",
                    "nistQuantumSecurityLevel": 5,
                    "classicalSecurityLevel": 256,
                    "quantumSecurity": "quantum-safe",
                    "standards": ["FIPS 204", "NSA CNSA 2.0"],
                    "publicKeyLength": 2592,
                    "secretKeyLength": 4896,
                    "signatureLength": 4627,
                    "implementation": "LibOQS native C assembly",
                }
            }
        },
        {
            "type": "cryptographic-asset",
            "name": "SLH-DSA-Pure-SHAKE-256f",
            "version": "FIPS 205 (Final 2024)",
            "description": "Secondary Stateless Hash-Based Signature for Root Certificates and Firmware Signing",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "signature",
                    "parameterSetIdentifier": "slh-dsa-pure-shake-256f",
                    "nistQuantumSecurityLevel": 5,
                    "classicalSecurityLevel": 256,
                    "quantumSecurity": "quantum-safe",
                    "standards": ["FIPS 205"],
                    "publicKeyLength": 64,
                    "secretKeyLength": 128,
                    "signatureLength": 49856,
                    "implementation": "LibOQS native C",
                }
            }
        },
        {
            "type": "cryptographic-asset",
            "name": "FALCON-1024",
            "version": "pre-standard Falcon (NOT FN-DSA; FIPS 206 draft track only)",
            "description": "NIST Level 5 Fast Lattice Signature over NTRU lattices for compact low-bandwidth payloads. Round-3 Falcon wire format is NOT byte-compatible with final FN-DSA; excluded as primary.",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "signature",
                    "parameterSetIdentifier": "falcon-1024",
                    "nistQuantumSecurityLevel": 5,
                    "classicalSecurityLevel": 256,
                    "quantumSecurity": "quantum-safe",
                    "standards": ["NIST PQC Round-3 candidate", "FIPS 206 draft track (excluded as primary)"],
                    "publicKeyLength": 1793,
                    "secretKeyLength": 2305,
                    "signatureLength": 1462,
                    "implementation": "LibOQS native C",
                }
            }
        },
        # --- Symmetric AEAD & Hashing (FIPS 197 / RFC 8439 / FIPS 202) ---
        {
            "type": "cryptographic-asset",
            "name": "AES-256-GCM",
            "version": "FIPS 197 / NIST SP 800-38D",
            "description": "Authenticated Encryption with Associated Data (CNSA 2.0 mandatory symmetric floor)",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "block-cipher",
                    "mode": "gcm",
                    "keyLength": 256,
                    "tagLength": 128,
                    "ivLength": 96,
                    "quantumSecurity": "quantum-resistant",
                    "standards": ["FIPS 197", "NIST SP 800-38D", "CNSA 2.0"],
                    "implementation": "OpenSSL / PyCA Cryptography AES-NI hardware accelerated",
                }
            }
        },
        {
            "type": "cryptographic-asset",
            "name": "ChaCha20-Poly1305",
            "version": "RFC 8439",
            "description": "High-Speed Stream Cipher AEAD with constant-time software side-channel immunity",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "stream-cipher",
                    "keyLength": 256,
                    "tagLength": 128,
                    "nonceLength": 96,
                    "quantumSecurity": "quantum-resistant",
                    "standards": ["RFC 8439"],
                    "implementation": "Rust Data Plane (destroyer_core) + Libsodium",
                }
            }
        },
        {
            "type": "cryptographic-asset",
            "name": "SHA3-512 & SHAKE-256",
            "version": "FIPS 202 (Keccak)",
            "description": "Permutation-based Secure Hash and Extendable-Output Function for transcript chaining",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "hash-and-xof",
                    "digestLength": 512,
                    "quantumSecurity": "quantum-safe",
                    "standards": ["FIPS 202", "CNSA 2.0"],
                    "implementation": "Python hashlib / OpenSSL 3.0",
                }
            }
        },
        {
            "type": "cryptographic-asset",
            "name": "HKDF-SHA384 / HKDF-SHA3-512",
            "version": "RFC 5869",
            "description": "HMAC-based Extract-and-Expand Key Derivation Function for hybrid secret combination",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "kdf",
                    "hashFunction": "SHA-384 and SHA3-512",
                    "quantumSecurity": "quantum-safe",
                    "standards": ["RFC 5869", "NIST SP 800-56C"],
                    "implementation": "Native Python & OpenSSL",
                }
            }
        },
        # --- Cryptographic Protocols ---
        {
            "type": "cryptographic-asset",
            "name": "Post-Quantum Double Ratchet Protocol",
            "version": "NIST Level 5 PQ Extension",
            "description": "End-to-End messaging protocol providing Continuous Forward Secrecy and Post-Compromise Security",
            "cryptoProperties": {
                "assetType": "protocol",
                "algorithmProperties": {
                    "rootKDF": "HKDF-SHA384",
                    "chainKDF": "HMAC-SHA256",
                    "kemRatchet": "ML-KEM-1024 + Classic-McEliece-8192128f",
                    "signatureRatchet": "ML-DSA-87",
                    "aead": "ChaCha20-Poly1305 / AES-256-GCM",
                    "quantumSecurity": "quantum-safe",
                }
            }
        },
        {
            "type": "cryptographic-asset",
            "name": "Mutual TLS 1.3 with Sovereign ML-DSA-87 Certificates",
            "version": "RFC 8446 Strict Sovereign Profile",
            "description": "Zero-Plaintext, mutual certificate-authenticated channel with PQC identity validation",
            "cryptoProperties": {
                "assetType": "protocol",
                "algorithmProperties": {
                    "tlsVersion": "TLS 1.3 (Strict)",
                    "mutualAuth": True,
                    "certSignature": "ML-DSA-87 (FIPS 204)",
                    "kemKeyExchange": "ML-KEM-1024 (FIPS 203)",
                    "quantumSecurity": "quantum-safe",
                }
            }
        },
        {
            "type": "cryptographic-asset",
            "name": "WireGuard-Style Rust UDP Data Plane",
            "version": "destroyer_core v0.1.0",
            "description": "Dual-stack IPv6/IPv4 silent-drop UDP transport with 1280B fixed quanta and anti-replay window",
            "cryptoProperties": {
                "assetType": "protocol",
                "algorithmProperties": {
                    "transport": "UDP (Dual-Stack IPv6/IPv4)",
                    "mtuBudget": 1280,
                    "paddingQuanta": [256, 512, 1232],
                    "antiReplay": "64-bit sliding window bitmap",
                    "rateLimiting": "Token-bucket (64 capacity, 16/sec refill)",
                    "blackHoleDiscipline": True,
                    "zeroizeOnDrop": True,
                }
            }
        },
        # --- Hardware Root of Trust ---
        {
            "type": "cryptographic-asset",
            "name": "Physical TPM 2.0 Hardware Security Module",
            "version": "TPM 2.0 CRB (AMD PSP 10.0 / ACPI\\MSFT0101\\1)",
            "description": "Hardware Root-of-Trust with physical PCR registers (0, 1, 2, 7) read via Win32 TBS (tbs.dll)",
            "cryptoProperties": {
                "assetType": "hardware-root-of-trust",
                "algorithmProperties": {
                    "interface": "Win32 TPM Base Services (tbs.dll: Tbsip_Submit_Command)",
                    "pcrBank": "SHA-256 (0x000B)",
                    "activePCRs": [0, 1, 2, 7],
                    "secureBootBound": True,
                    "attestationSignature": "ML-DSA-87",
                    "hardwareMode": "HARDWARE_ROOT_ENFORCED",
                }
            }
        }
    ]

    cbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Sovereign Military Defense P2P Platform",
                        "version": "2028.1.0-DEFENSE",
                        "description": "NSA CNSA 2.0 & FIPS 140-3 Sovereign Tactical Communications Asset"
                    }
                ]
            },
            "authors": [
                {
                    "name": "Sovereign Defense Architecture Directorate",
                    "role": "Cryptographic Engineering & National Security Compliance"
                }
            ],
            "properties": [
                {"name": "cnsa2_compliance_gate", "value": "2027-01-01 (Mandatory New Acquisition)"},
                {"name": "nist_security_level", "value": "Level 5 (256-bit Post-Quantum Floor)"},
                {"name": "fail_closed_guarantee", "value": "Zero Silent Fallbacks Permitted"}
            ]
        },
        "components": crypto_components
    }

    return cbom


def sign_and_export_cbom(output_dir: Path | None = None) -> Tuple[Path, Path, Path]:
    """Generate CBOM JSON and sign with ML-DSA-87 digital signature."""
    out_dir = output_dir or (REPO_ROOT / "compliance_reports")
    out_dir.mkdir(parents=True, exist_ok=True)

    cbom_data = generate_cbom_data()
    cbom_path = out_dir / "cyclonedx_cbom.json"
    cbom_bytes = json.dumps(cbom_data, indent=2).encode("utf-8")
    cbom_path.write_bytes(cbom_bytes)

    # Generate ML-DSA-87 signature over exact canonical JSON bytes
    sig_engine = LibOQS_MLDSA_87()
    pk, sk = sig_engine.keygen()
    sig = sig_engine.sign(sk, cbom_bytes)

    sig_path = out_dir / "cyclonedx_cbom.json.mldsa87.sig"
    pub_path = out_dir / "cyclonedx_cbom.json.mldsa87.pub"

    sig_path.write_bytes(sig)
    pub_path.write_bytes(pk)

    print(f"[*] Generated CycloneDX 1.6 CBOM: {cbom_path} ({len(cbom_data['components'])} crypto assets)")
    print(f"[*] Signed with ML-DSA-87 (FIPS 204): {sig_path} (sig={len(sig)}B)")
    print(f"[*] Public verification key exported: {pub_path} (pk={len(pk)}B)")

    return cbom_path, sig_path, pub_path


def verify_cbom_signature(cbom_path: Path, sig_path: Path, pub_path: Path) -> bool:
    """Verify ML-DSA-87 signature over generated CBOM."""
    if not (cbom_path.exists() and sig_path.exists() and pub_path.exists()):
        print(f"[FAIL] Missing CBOM or signature sidecars: {cbom_path}, {sig_path}, {pub_path}")
        return False

    raw_json = cbom_path.read_bytes()
    sig = sig_path.read_bytes()
    pk = pub_path.read_bytes()

    sig_engine = LibOQS_MLDSA_87()
    valid = sig_engine.verify(pk, raw_json, sig)
    if valid:
        print(f"[PASS] Cryptographic verification: CBOM signature VERIFIED with ML-DSA-87 (FIPS 204)")
    else:
        print(f"[FAIL] Cryptographic verification: CBOM signature INVALID or TAMPERED")
    return valid


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate and verify CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)")
    parser.add_argument("--verify", action="store_true", help="Verify existing CBOM signature")
    parser.add_argument("--output-dir", type=str, default=None, help="Output directory")
    args = parser.parse_args()

    out_dir = Path(args.output_dir) if args.output_dir else (REPO_ROOT / "compliance_reports")
    cbom_file = out_dir / "cyclonedx_cbom.json"
    sig_file = out_dir / "cyclonedx_cbom.json.mldsa87.sig"
    pub_file = out_dir / "cyclonedx_cbom.json.mldsa87.pub"

    if args.verify:
        verified = verify_cbom_signature(cbom_file, sig_file, pub_file)
        sys.exit(0 if verified else 1)
    else:
        c_path, s_path, p_path = sign_and_export_cbom(out_dir)
        verified = verify_cbom_signature(c_path, s_path, p_path)
        sys.exit(0 if verified else 1)
