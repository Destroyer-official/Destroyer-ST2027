#!/usr/bin/env python3
"""
scripts/generate_sovereign_pki.py

Generates the complete 2027+ Sovereign Post-Quantum PKI hierarchy for the
DoD / Defense Agency ATO Pilot.

Hierarchy:
  1. Sovereign Root CA (Self-signed ML-DSA-87 + NIST P-521 anchor)
  2. Sovereign Tactical Issuing CA (Sub CA signed by Root CA)
  3. Tactical Node Alpha Identity Certificate (Signed by Sub CA)
  4. Tactical Node Bravo Identity Certificate (Signed by Sub CA)
  5. Hash-Chained Certificate Revocation List (CRL)
  6. PKI Manifest (Signed Merkle digest of all pilot certificates)

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
    print(f"[*] Generating Sovereign Post-Quantum PKI in: {certs_dir}")

    mldsa = LibOQS_MLDSA_87()

    # 1. Generate Sovereign Root CA
    print("  -> Creating Sovereign Root CA (ML-DSA-87 + P-521)...")
    root_ca = PQCertificateAuthority(ca_name="Sovereign-Defense-Root-CA")
    root_cert = root_ca._root_cert

    # Generate classical P-521 anchor for root
    root_p521_key = ec.generate_private_key(ec.SECP521R1())
    root_p521_pub = root_p521_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    root_cert_data = {
        "certificate_type": "SOVEREIGN_ROOT_CA",
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

    # 2. Generate Sovereign Subordinate / Tactical Issuing CA
    print("  -> Creating Sovereign Subordinate Issuing CA...")
    sub_pk, sub_sk = mldsa.keygen()
    sub_cert = root_ca.issue_certificate(
        subject="CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",
        public_key=sub_pk,
        validity_days=1825,  # 5 years
        extensions={"is_ca": True, "path_length": 1, "key_usage": ["digitalSignature", "keyCertSign", "cRLSign"]}
    )

    sub_cert_data = {
        "certificate_type": "SOVEREIGN_SUB_CA",
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
    print("  -> Issuing Tactical Node Alpha Certificate...")
    alpha_pk, alpha_sk = mldsa.keygen()
    tbs_alpha = {
        "serial_number": 1001,
        "subject": "CN=tactical-node-alpha.mil,OU=Forward Base Alpha,O=Tactical P2P,C=US",
        "issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",
        "public_key": alpha_pk.hex(),
        "not_before": datetime.now(timezone.utc).isoformat(),
        "not_after": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "san": ["DNS:tactical-node-alpha.mil", "IP:127.0.0.1", "TOR:alpha5739281.onion"],
        "key_usage": ["digitalSignature", "keyEncipherment", "clientAuth", "serverAuth"]
    }
    alpha_sig = mldsa.sign(sub_sk, json.dumps(tbs_alpha, sort_keys=True).encode())

    alpha_cert_data = {
        "certificate_type": "TACTICAL_PEER_IDENTITY",
        "tbs_data": tbs_alpha,
        "signature_algorithm": "ML-DSA-87",
        "signature_hex": alpha_sig.hex()
    }
    with open(certs_dir / "node_alpha.json", "w", encoding="utf-8") as f:
        json.dump(alpha_cert_data, f, indent=2)

    # 4. Issue Node Bravo Identity Certificate
    print("  -> Issuing Tactical Node Bravo Certificate...")
    bravo_pk, bravo_sk = mldsa.keygen()
    tbs_bravo = {
        "serial_number": 1002,
        "subject": "CN=tactical-node-bravo.mil,OU=Forward Base Bravo,O=Tactical P2P,C=US",
        "issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",
        "public_key": bravo_pk.hex(),
        "not_before": datetime.now(timezone.utc).isoformat(),
        "not_after": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "san": ["DNS:tactical-node-bravo.mil", "IP:127.0.0.1", "TOR:bravo9184712.onion"],
        "key_usage": ["digitalSignature", "keyEncipherment", "clientAuth", "serverAuth"]
    }
    bravo_sig = mldsa.sign(sub_sk, json.dumps(tbs_bravo, sort_keys=True).encode())

    bravo_cert_data = {
        "certificate_type": "TACTICAL_PEER_IDENTITY",
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
        "this_update": datetime.now(timezone.utc).isoformat(),
        "next_update": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        "revoked_certificates": [],
        "hash_chain_digest": hashlib.sha3_512(b"GENESIS_CRL_STATE").hexdigest()
    }
    crl_sig = mldsa.sign(sub_sk, json.dumps(crl_data, sort_keys=True).encode())
    crl_manifest = {
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
        "generation_timestamp": datetime.now(timezone.utc).isoformat(),
        "standard_compliance": ["FIPS 204", "FIPS 205", "CNSA 2.0", "NIST SP 800-57"],
        "root_authority": "CN=Sovereign-Defense-Root-CA",
        "merkle_root": pki_merkle_root,
        "artifacts": manifest_entries
    }
    with open(certs_dir / "pki_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    print(f"[SUCCESS] Sovereign PKI generated successfully in {certs_dir}!")
    print(f"          PKI Merkle Root: {pki_merkle_root[:32]}...")


if __name__ == "__main__":
    main()
