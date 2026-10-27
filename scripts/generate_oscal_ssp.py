#!/usr/bin/env python3
"""
generate_oscal_ssp.py
Generates official NIST OSCAL (Open Security Controls Assessment Language) v1.1.0
System Security Plan (SSP) and Security Controls Traceability Matrix (SCTM)
mapped to NIST SP 800-53 Rev 5 and CNSSI 1253 for the Sovereign Military Defense Platform.

Cryptographically signed with Post-Quantum ML-DSA-87 (FIPS 204).
"""

import argparse
import datetime
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Tuple
import uuid

_this_dir = Path(__file__).resolve().parent
REPO_ROOT = _this_dir.parent if _this_dir.name == "scripts" else _this_dir

try:
    from liboqs_wrapper import LibOQS_MLDSA_87
except ImportError:
    sys.path.insert(0, str(REPO_ROOT))
    from liboqs_wrapper import LibOQS_MLDSA_87


def generate_oscal_ssp_data() -> Dict[str, Any]:
    """Build canonical NIST OSCAL v1.1.0 System Security Plan (SSP) JSON data."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    ssp_id = str(uuid.uuid4())

    ssp = {
        "system-security-plan": {
            "id": ssp_id,
            "metadata": {
                "title": "Sovereign Military P2P Communications Platform - System Security Plan (SSP)",
                "published": timestamp,
                "last-modified": timestamp,
                "version": "2028.1.0-DEFENSE",
                "oscal-version": "1.1.0",
                "remarks": "SELF-AUTHORED SSP DRAFT for AO package assembly (not accredited; no AO action). Control coverage below is the implemented-boundary subset (12 controls); full High-baseline extension is tracked in the SAR POA&M.",
                "roles": [
                    {
                        "id": "authorizing-official",
                        "title": "Authorizing Official (AO)",
                        "description": "Designated Senior Defense Official with authority to grant formal Authority to Operate (ATO)."
                    },
                    {
                        "id": "information-system-security-officer",
                        "title": "Information System Security Officer (ISSO)",
                        "description": "Responsible for continuous monitoring and post-quantum cryptographic policy enforcement."
                    },
                    {
                        "id": "cryptographic-custodian",
                        "title": "Key Custodian / Cryptographic Officer",
                        "description": "Two-Person Rule / Dual Custody custodian for root ceremonies and M-of-N key recovery."
                    }
                ],
                "parties": [
                    {
                        "id": "sovereign-defense-hq",
                        "type": "organization",
                        "name": "Sovereign Defense Communications Command",
                        "email-addresses": ["crypto-command@defense.mil"]
                    }
                ]
            },
            "import-profile": {
                "href": "#local-cnsa2-strict-tailoring",
                "remarks": "No external profile imported (a prior draft cited a non-existent NIST URL; removed). Tailoring: CNSA 2.0 strict (ML-KEM-1024 + ML-DSA-87 mandatory; see cnsa2_policy_engine.py)."
            },
            "system-characteristics": {
                "system-name": "Sovereign Military P2P Tactical Mesh",
                "system-name-short": "Destroyer-P2P",
                "description": "Quantum-resistant, zero-trust, peer-to-peer tactical communications platform utilizing native FIPS 203/204/205 primitives, hardware TPM 2.0 PCR attestation, and WireGuard-style Rust UDP data plane.",
                "deployment-model": "private",
                "security-sensitivity-level": "strategic-national-security",
                "system-information": {
                    "information-types": [
                        {
                            "title": "National Security Communications (NC3 & Defense Mesh)",
                            "description": "Tactical voice, text, telemetry, and critical command authentication data.",
                            "categorization": {
                                "system": "http://doi.org/10.6028/NIST.SP.800-60v2r1",
                                "information-type-ids": ["D.1.1"]
                            },
                            "confidentiality-impact": { "base": "fips-199-high" },
                            "integrity-impact": { "base": "fips-199-high" },
                            "availability-impact": { "base": "fips-199-high" }
                        }
                    ]
                },
                "security-impact-level": {
                    "security-objective-confidentiality": "fips-199-high",
                    "security-objective-integrity": "fips-199-high",
                    "security-objective-availability": "fips-199-high"
                },
                "status": {
                    "state": "under-development",
                    "remarks": "Self-assessed development state; operational use requires AO authorization (not granted)."
                },
                "authorization-boundary": {
                    "description": "Encompasses local node memory, physical TPM 2.0 chip, native destroyer_core Rust execution boundary, and WireGuard UDP data plane sockets."
                }
            },
            "system-implementation": {
                "components": [
                    {
                        "id": "pqc-crypto-engine",
                        "type": "software",
                        "title": "Post-Quantum Cryptographic Engine (liboqs + destroyer_core)",
                        "description": "Executes FIPS 203 (ML-KEM-1024), FIPS 204 (ML-DSA-87), and FIPS 205 (SLH-DSA-256f).",
                        "purpose": "Provides quantum-resistant key encapsulation and digital signatures."
                    },
                    {
                        "id": "hardware-tpm-module",
                        "type": "hardware",
                        "title": "Hardware Root of Trust (Win32 TBS / TPM 2.0)",
                        "description": "Physical AMD PSP / Intel PTT TPM 2.0 providing PCR 0/1/2/7 measurement quotes.",
                        "purpose": "Protects root keys and provides remote platform attestation."
                    },
                    {
                        "id": "rust-udp-data-plane",
                        "type": "software",
                        "title": "WireGuard-Style Rust UDP Data Plane",
                        "description": "High-throughput asynchronous UDP transport with ChaCha20-Poly1305 AEAD and fixed quantum framing.",
                        "purpose": "Eliminates side-channel size leakage and provides silent-drop black-hole discipline."
                    },
                    {
                        "id": "siem-audit-engine",
                        "type": "software",
                        "title": "Tamper-Evident SIEM Audit Engine",
                        "description": "Generates forward-secure HMAC-SHA384 chained audit trails streamed over TLS 1.3.",
                        "purpose": "Supports forensic log integrity and anti-tamper detection (design goal, not a guarantee)."
                    }
                ]
            },
            "control-implementation": {
                "description": "Implemented-boundary control subset mapped to NIST SP 800-53 Rev 5 (12 controls with in-repo evidence). NOT full High-baseline coverage; extension tracked in SAR POA&M.",
                "implemented-requirements": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "ac-3",
                        "description": "Access Enforcement: Strict Zero-Trust RBAC engine enforces least privilege and default-deny.",
                        "by-components": [
                            {
                                "component-uuid": "pqc-crypto-engine",
                                "description": "Constant-time RBAC role evaluation; unauthenticated actions abort session fail-closed."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "ac-4",
                        "description": "Information Flow Enforcement: Enforces discrete traffic quantum shape and chaff absorption.",
                        "by-components": [
                            {
                                "component-uuid": "rust-udp-data-plane",
                                "description": "All messages padded to 256/512/1232B quanta. Datagrams exceeding 1280B IPv6 MTU silently dropped."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "au-2",
                        "description": "Event Logging: All authentication, key rotation, and packet drop events recorded.",
                        "by-components": [
                            {
                                "component-uuid": "siem-audit-engine",
                                "description": "Structured JSON logging with sequence numbers, UTC timestamps, and cryptographic fingerprints."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "au-9",
                        "description": "Protection of Audit Information: Audit logs protected via forward-secure HMAC-SHA384 chaining.",
                        "by-components": [
                            {
                                "component-uuid": "siem-audit-engine",
                                "description": "Each log entry incorporates the HMAC of the preceding entry. Modifying any log breaks chain verification."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "au-10",
                        "description": "Non-Repudiation: Every session transaction and certificate signed with ML-DSA-87.",
                        "by-components": [
                            {
                                "component-uuid": "pqc-crypto-engine",
                                "description": "FIPS 204 ML-DSA-87 digital signatures provide non-repudiable proof of sender identity."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "ia-2",
                        "description": "Identification and Authentication: Multi-factor and hardware-backed peer authentication.",
                        "by-components": [
                            {
                                "component-uuid": "hardware-tpm-module",
                                "description": "Remote attestation verifies genuine physical TPM 2.0 PCR registers (PCR 0, 1, 2, 7)."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "ia-5",
                        "description": "Authenticator Management: Post-quantum Double Ratchet provides forward secrecy and break-in recovery.",
                        "by-components": [
                            {
                                "component-uuid": "pqc-crypto-engine",
                                "description": "KEM ratchets advance keys every turn; root keys zeroized on drop."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "sc-8",
                        "description": "Transmission Confidentiality and Integrity: Dual-layer authenticated encryption over wire.",
                        "by-components": [
                            {
                                "component-uuid": "rust-udp-data-plane",
                                "description": "ChaCha20-Poly1305 native outer envelope wrapping inner Double Ratchet ciphertext."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "sc-12",
                        "description": "Cryptographic Key Establishment and Management: Post-quantum hybrid KEM and M-of-N Shamir backup.",
                        "by-components": [
                            {
                                "component-uuid": "pqc-crypto-engine",
                                "description": "ML-KEM-1024 (FIPS 203) with HKDF-SHA384 domain separation and dual-custody recovery ceremonies."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "sc-13",
                        "description": "Cryptographic Protection: NIST Level 5+ algorithms conforming strictly to NSA CNSA 2.0.",
                        "by-components": [
                            {
                                "component-uuid": "pqc-crypto-engine",
                                "description": "AES-256-GCM, ChaCha20-Poly1305, ML-KEM-1024, ML-DSA-87, SLH-DSA-256f. Zero legacy ciphers permitted."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "si-4",
                        "description": "Information System Monitoring: Anti-replay sliding window and token-bucket flood prevention.",
                        "by-components": [
                            {
                                "component-uuid": "rust-udp-data-plane",
                                "description": "64-bit sliding window bitmap rejects packet replays; token-bucket limits bursts to 64 datagrams."
                            }
                        ]
                    },
                    {
                        "uuid": str(uuid.uuid4()),
                        "control-id": "si-7",
                        "description": "Software, Firmware, and Information Integrity: CycloneDX 1.6 CBOM and TUF anti-rollback.",
                        "by-components": [
                            {
                                "component-uuid": "pqc-crypto-engine",
                                "description": "Cryptographic bill of materials and software binaries signed with ML-DSA-87."
                            }
                        ]
                    }
                ]
            }
        }
    }

    return ssp


def sign_and_export_oscal_ssp(output_dir: Path | None = None) -> Tuple[Path, Path, Path]:
    """Generate OSCAL SSP JSON and sign with ML-DSA-87 digital signature."""
    out_dir = output_dir or (REPO_ROOT / "compliance_reports")
    out_dir.mkdir(parents=True, exist_ok=True)

    ssp_data = generate_oscal_ssp_data()
    ssp_path = out_dir / "oscal_ssp_cnsa2.json"
    ssp_bytes = json.dumps(ssp_data, indent=2).encode("utf-8")
    ssp_path.write_bytes(ssp_bytes)

    sig_engine = LibOQS_MLDSA_87()
    pk, sk = sig_engine.keygen()
    sig = sig_engine.sign(sk, ssp_bytes)

    sig_path = out_dir / "oscal_ssp_cnsa2.json.mldsa87.sig"
    pub_path = out_dir / "oscal_ssp_cnsa2.json.mldsa87.pub"

    sig_path.write_bytes(sig)
    pub_path.write_bytes(pk)

    print(f"[*] Generated OSCAL v1.1.0 SSP: {ssp_path}")
    print(f"[*] Signed with ML-DSA-87 (FIPS 204): {sig_path} (sig={len(sig)}B)")
    print(f"[*] Public key exported: {pub_path} (pk={len(pk)}B)")

    return ssp_path, sig_path, pub_path


def verify_oscal_ssp_signature(ssp_path: Path, sig_path: Path, pub_path: Path) -> bool:
    """Verify ML-DSA-87 signature over generated OSCAL SSP JSON."""
    if not (ssp_path.exists() and sig_path.exists() and pub_path.exists()):
        print(f"[FAIL] Missing OSCAL SSP or signature sidecars: {ssp_path}, {sig_path}, {pub_path}")
        return False

    raw_json = ssp_path.read_bytes()
    sig = sig_path.read_bytes()
    pk = pub_path.read_bytes()

    sig_engine = LibOQS_MLDSA_87()
    valid = sig_engine.verify(pk, raw_json, sig)
    if valid:
        print("[PASS] Cryptographic verification: OSCAL SSP signature VERIFIED with ML-DSA-87 (FIPS 204)")
    else:
        print("[FAIL] Cryptographic verification: OSCAL SSP signature INVALID or TAMPERED")
    return valid


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate and verify NIST OSCAL v1.1.0 System Security Plan (SSP)")
    parser.add_argument("--verify", action="store_true", help="Verify existing OSCAL SSP signature")
    parser.add_argument("--output-dir", type=str, default=None, help="Output directory")
    args = parser.parse_args()

    out_dir = Path(args.output_dir) if args.output_dir else (REPO_ROOT / "compliance_reports")
    ssp_file = out_dir / "oscal_ssp_cnsa2.json"
    sig_file = out_dir / "oscal_ssp_cnsa2.json.mldsa87.sig"
    pub_file = out_dir / "oscal_ssp_cnsa2.json.mldsa87.pub"

    if args.verify:
        success = verify_oscal_ssp_signature(ssp_file, sig_file, pub_file)
        sys.exit(0 if success else 1)
    else:
        sign_and_export_oscal_ssp(out_dir)
        success = verify_oscal_ssp_signature(ssp_file, sig_file, pub_file)
        sys.exit(0 if success else 1)
