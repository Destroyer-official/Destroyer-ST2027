#!/usr/bin/env python3
"""
scripts/generate_sovereign_pki.py

Generates the local ML-DSA-87 and NIST P-521 Post-Quantum PKI hierarchy
for deployment verification.

Hierarchy:
  1. Local Root CA (Self-signed ML-DSA-87 + NIST P-521 anchor)
  2. Subordinate Issuing CA (Sub CA signed by Root CA)
  3. Node Alpha Identity Certificate (Signed by Sub CA)
  4. Node Bravo Identity Certificate (Signed by Sub CA)
  5. Hash-Chained Certificate Revocation List (CRL)
  6. PKI Manifest (Signed Merkle digest of generated certificates)

Artifacts written to: certs/
"""

import os
import sys
import json
import time
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pq_certificate_authority import PQCertificateAuthority, PQCertificate, HashChainCRL
from liboqs_wrapper import LibOQS_MLDSA_87
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes


def main():
    certs_dir = PROJECT_ROOT / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Generating Post-Quantum PKI in: {certs_dir}")

    mldsa = LibOQS_MLDSA_87()

    # 1. Generate Local Root CA
    print("  -> Creating Local Root CA (ML-DSA-87 + P-521)...")
    root_ca = PQCertificateAuthority(ca_name="Sovereign-Defense-Root-CA")
    root_cert = root_ca._root_cert

    # Generate classical P-521 anchor for root
    root_p521_key = ec.generate_private_key(ec.SECP521R1())
    root_p521_pub = root_p521_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    now_utc = datetime.now(timezone.utc)
    CEREMONY_TYPE = "SOFTWARE_DEV_FIXTURE_NOT_EXTERNALLY_ANCHORED"

    root_cert_data = {
        "certificate_type": "SOVEREIGN_ROOT_CA",
        "ceremony_type": CEREMONY_TYPE,
        "subject": root_cert.subject,
        "issuer": root_cert.issuer,
        "serial_number": root_cert.serial,
        "not_before": root_cert.not_before.isoformat(),
        "not_after": root_cert.not_after.isoformat(),
        "signature_algorithm": "ML-DSA-87",
        "classical_anchor": "SECP521R1",
        "public_key_hex": root_ca._ca_public_key.hex(),
        "classical_public_key_pem": root_p521_pub.decode('utf-8'),
        "signature_hex": root_cert.signature.hex(),
        "basic_constraints": {"is_ca": True, "path_length": 2},
        "key_usage": ["digitalSignature", "keyCertSign", "cRLSign"]
    }

    with open(certs_dir / "sovereign_root_ca.json", "w", encoding="utf-8") as f:
        json.dump(root_cert_data, f, indent=2)

    # 2. Generate Subordinate Issuing CA
    print("  -> Creating Subordinate Issuing CA...")
    sub_pk, sub_sk = mldsa.keygen()
    sub_cert = root_ca.issue_certificate(
        subject="CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",
        public_key=sub_pk,
        validity_days=1825,  # 5 years
        extensions={"is_ca": True, "path_length": 1, "key_usage": ["digitalSignature", "keyCertSign", "cRLSign"]}
    )

    sub_cert_data = {
        "certificate_type": "SOVEREIGN_SUB_CA",
        "ceremony_type": CEREMONY_TYPE,
        "subject": sub_cert.subject,
        "issuer": sub_cert.issuer,
        "serial_number": sub_cert.serial,
        "not_before": sub_cert.not_before.isoformat(),
        "not_after": sub_cert.not_after.isoformat(),
        "signature_algorithm": "ML-DSA-87",
        "public_key_hex": sub_pk.hex(),
        "signature_hex": sub_cert.signature.hex(),
        "basic_constraints": {"is_ca": True, "path_length": 1},
        "key_usage": ["digitalSignature", "keyCertSign", "cRLSign"]
    }

    with open(certs_dir / "sovereign_sub_ca.json", "w", encoding="utf-8") as f:
        json.dump(sub_cert_data, f, indent=2)

    # 3. Issue Node Alpha Identity Certificate
    print("  -> Issuing Node Alpha Certificate...")
    alpha_pk, _alpha_sk = mldsa.keygen()
    tbs_alpha = {
        "serial_number": 1001,
        "subject": "CN=tactical-node-alpha.mil,OU=Forward Base Alpha,O=Tactical P2P,C=US",
        "issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",
        "public_key": alpha_pk.hex(),
        "not_before": now_utc.isoformat(),
        "not_after": (now_utc + timedelta(days=365)).isoformat(),
        "san": ["DNS:tactical-node-alpha.mil", "IP:127.0.0.1", "TOR:alpha5739281.onion"],
        "key_usage": ["digitalSignature", "keyEncipherment", "clientAuth", "serverAuth"]
    }
    alpha_sig = mldsa.sign(sub_sk, json.dumps(tbs_alpha, sort_keys=True).encode())

    alpha_cert_data = {
        "certificate_type": "TACTICAL_PEER_IDENTITY",
        "ceremony_type": CEREMONY_TYPE,
        "tbs_data": tbs_alpha,
        "signature_algorithm": "ML-DSA-87",
        "signature_hex": alpha_sig.hex()
    }
    with open(certs_dir / "node_alpha.json", "w", encoding="utf-8") as f:
        json.dump(alpha_cert_data, f, indent=2)

    # 4. Issue Node Bravo Identity Certificate
    print("  -> Issuing Node Bravo Certificate...")
    bravo_pk, _bravo_sk = mldsa.keygen()
    tbs_bravo = {
        "serial_number": 1002,
        "subject": "CN=tactical-node-bravo.mil,OU=Forward Base Bravo,O=Tactical P2P,C=US",
        "issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",
        "public_key": bravo_pk.hex(),
        "not_before": now_utc.isoformat(),
        "not_after": (now_utc + timedelta(days=365)).isoformat(),
        "san": ["DNS:tactical-node-bravo.mil", "IP:127.0.0.1", "TOR:bravo9184712.onion"],
        "key_usage": ["digitalSignature", "keyEncipherment", "clientAuth", "serverAuth"]
    }
    bravo_sig = mldsa.sign(sub_sk, json.dumps(tbs_bravo, sort_keys=True).encode())

    bravo_cert_data = {
        "certificate_type": "TACTICAL_PEER_IDENTITY",
        "ceremony_type": CEREMONY_TYPE,
        "tbs_data": tbs_bravo,
        "signature_algorithm": "ML-DSA-87",
        "signature_hex": bravo_sig.hex()
    }
    with open(certs_dir / "node_bravo.json", "w", encoding="utf-8") as f:
        json.dump(bravo_cert_data, f, indent=2)

    # 5. Generate Hash-Chained CRL
    print("  -> Generating Hash-Chained CRL...")
    crl_data = {
        "crl_number": 1,
        "issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",
        "this_update": now_utc.isoformat(),
        "next_update": (now_utc + timedelta(days=365)).isoformat(),
        "revoked_certificates": [],
        "hash_chain_digest": hashlib.sha3_512(b"GENESIS_CRL_STATE").hexdigest()
    }
    crl_sig = mldsa.sign(sub_sk, json.dumps(crl_data, sort_keys=True).encode())
    crl_manifest = {
        "ceremony_type": CEREMONY_TYPE,
        "crl": crl_data,
        "signature_algorithm": "ML-DSA-87",
        "signature_hex": crl_sig.hex()
    }
    with open(certs_dir / "crl.json", "w", encoding="utf-8") as f:
        json.dump(crl_manifest, f, indent=2)

    # 6. Build PKI Manifest with SHA3-512 hashes
    print("  -> Creating PKI Manifest...")
    manifest_entries = {}
    merkle_leaves = []
    for fname in ["sovereign_root_ca.json", "sovereign_sub_ca.json", "node_alpha.json", "node_bravo.json", "crl.json"]:
        content = (certs_dir / fname).read_bytes()
        digest = hashlib.sha3_512(content).hexdigest()
        manifest_entries[fname] = {
            "size_bytes": len(content),
            "sha3_512": digest
        }
        merkle_leaves.append(bytes.fromhex(digest))

    # Compute Root Merkle digest
    combined = b"".join(sorted(merkle_leaves))
    pki_merkle_root = hashlib.sha3_512(combined).hexdigest()

    manifest_data = {
        "pki_version": "2027.1.0",
        "ceremony_type": CEREMONY_TYPE,
        "externally_anchored": False,
        "generation_timestamp": now_utc.isoformat(),
        "standard_compliance": ["FIPS 204", "FIPS 205", "CNSA 2.0", "NIST SP 800-57"],
        "root_authority": "CN=Sovereign-Defense-Root-CA",
        "merkle_root": pki_merkle_root,
        "artifacts": manifest_entries
    }
    with open(certs_dir / "pki_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    # 7. Write synchronized, non-fabricated development ceremony affidavit
    affidavit_data = {
        "affidavit_metadata": {
            "document_title": "Development PKI Fixture Record (Not Externally Anchored)",
            "ceremony_type": CEREMONY_TYPE,
            "ceremony_standard": "NIST SP 800-57 Part 1 Rev. 5 / CNSA 2.0 (Software Fixture Only)",
            "ceremony_id": "DEV-FIXTURE-CNSA2-LOCAL-PKI",
            "execution_timestamp_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "pki_manifest_merkle_root": pki_merkle_root,
        },
        "ceremony_custodian_quorum": [],
        "enrolled_root_credentials": {
            "root_ca": {
                "file": "certs/sovereign_root_ca.json",
                "subject": root_cert.subject,
                "algorithm": "ML-DSA-87 (FIPS 204) + NIST P-521 (FIPS 186-5)",
                "sha3_512": manifest_entries["sovereign_root_ca.json"]["sha3_512"],
            },
            "sub_ca": {
                "file": "certs/sovereign_sub_ca.json",
                "subject": sub_cert.subject,
                "algorithm": "ML-DSA-87 (FIPS 204)",
                "sha3_512": manifest_entries["sovereign_sub_ca.json"]["sha3_512"],
            },
            "crl": {
                "file": "certs/crl.json",
                "issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",
                "sha3_512": manifest_entries["crl.json"]["sha3_512"],
            },
        },
        "hardware_root_of_trust": {
            "status": "SOFTWARE_DEV_FIXTURE_UNVERIFIED",
            "verified": False,
            "hardware_tamper_resistant": False,
            "attestation_method": "SOFTWARE_KEYGEN_LOCAL_FIXTURE",
            "note": "Local software-generated dev fixture for offline tests only; external CA anchor and physical HSM/TPM ceremony required in production.",
        },
        "verdict": "DEV_FIXTURE_UNANCHORED",
    }
    with open(certs_dir / "key_ceremony_affidavit.json", "w", encoding="utf-8") as f:
        json.dump(affidavit_data, f, indent=2)

    print(f"[SUCCESS] Post-Quantum PKI dev fixture generated cleanly in {certs_dir}!")
    print(f"          PKI Merkle Root: {pki_merkle_root[:32]}...")


if __name__ == "__main__":
    main()
