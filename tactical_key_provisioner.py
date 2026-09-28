#!/usr/bin/env python3
"""
================================================================================
  DEPARTMENT OF DEFENSE // STRATEGIC COMMUNICATIONS COMMAND
  TACTICAL AIR-GAPPED KEY & PEER PROVISIONER (CNSA 2.0 / FIPS 140-3)
================================================================================
Generates offline cryptographic credentials, certificates, and pre-shared
fingerprint whitelists for sovereign, zero-trust military P2P nodes.
Eliminates reliance on opportunistic public-internet certificate exchanges.
"""

import os
import sys
import json
import secrets
import hashlib
from typing import Dict, Any, Tuple, Optional, List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from ca_services import CAExchange

class SecurityError(Exception):
    """Raised when cryptographic security constraints or credential protections are violated."""

GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def generate_node_credentials(node_name: str, key_type: str = "mldsa87", validity_days: int = 365) -> Dict[str, Any]:
    """Generate self-signed certificate and private key for a military node using NIST Level 5 PQC."""
    ca = CAExchange(key_type=key_type, validity_days=validity_days, secure_exchange=True)
    key_pem, cert_pem = ca.generate_self_signed()
    fingerprint = ca.local_cert_fingerprint

    return {
        "node_name": node_name,
        "key_pem": key_pem.decode('utf-8'),
        "cert_pem": cert_pem.decode('utf-8'),
        "fingerprint": fingerprint,
        "key_type": key_type,
        "validity_days": validity_days
    }


def save_encrypted_credential(file_path: str, data: bytes, passphrase: Optional[str] = None) -> None:
    """Save credential file encrypted at rest using authenticated AES-256-GCM."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    pw = passphrase or os.environ.get("P2P_TACTICAL_KEY_PW")
    if not pw:
        raise SecurityError(
            "Hardcoded encryption secrets prohibited: neither passphrase parameter nor "
            "P2P_TACTICAL_KEY_PW environment variable was provided."
        )

    salt = secrets.token_bytes(32)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=210_000,
        backend=default_backend()
    )
    key = kdf.derive(pw.encode('utf-8'))
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    aad = os.path.basename(file_path).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, data, aad)
    payload = b"ENC_KEY_V1" + salt + nonce + ciphertext

    with open(file_path, "wb") as f:
        f.write(payload)
    if hasattr(os, 'chmod'):
        os.chmod(file_path, 0o600)


def load_encrypted_credential(file_path: str, passphrase: Optional[str] = None) -> bytes:
    """Load and decrypt credential file. Fails closed if corrupt or unauthenticated."""
    with open(file_path, "rb") as f:
        raw = f.read()

    if raw.startswith(b"ENC_KEY_V1"):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend

        salt = raw[10:42]
        nonce = raw[42:54]
        ciphertext = raw[54:]
        pw = passphrase or os.environ.get("P2P_TACTICAL_KEY_PW")
        if not pw:
            raise SecurityError(
                "Decryption failed: neither passphrase parameter nor P2P_TACTICAL_KEY_PW "
                "environment variable was provided."
            )
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=210_000,
            backend=default_backend()
        )
        key = kdf.derive(pw.encode('utf-8'))
        aesgcm = AESGCM(key)
        aad = os.path.basename(file_path).encode('utf-8')
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise SecurityError(
                f"Decryption failed for {file_path}: invalid passphrase, corrupted data, "
                f"or non-compliant legacy PBKDF2 iterations (CNSA 2.0 requires 210,000 PBKDF2-SHA512 iterations)."
            ) from e

    # Public certificates are permissible in PEM format; secret keys and tokens must be encrypted
    if b"PRIVATE KEY" in raw or file_path.endswith(".key"):
        raise SecurityError(f"Unencrypted private credential rejected for {file_path}. Plaintext secret keys prohibited.")

    return raw


def provision_tactical_network(output_dir: Optional[str] = None, passphrase: Optional[str] = None) -> Dict[str, Any]:
    """Provision complete credentials for Base Alpha and Base Bravo with mutual whitelisting."""
    if output_dir is None:
        output_dir = os.path.join(BASE_DIR, "credentials")
    os.makedirs(output_dir, exist_ok=True)

    pw = passphrase or os.environ.get("P2P_TACTICAL_KEY_PW")
    minted_here = False
    if not pw:
        pw = secrets.token_hex(32)
        os.environ["P2P_TACTICAL_KEY_PW"] = pw
        minted_here = True
        print(f"  [SECURITY] Generated ephemeral 256-bit tactical key passphrase for provisioning.")

    print(f"\n{BOLD}{CYAN}{'='*80}{RESET}")
    print(f"{BOLD}{CYAN}  PROVISIONING AIR-GAPPED TACTICAL CREDENTIALS (CNSA 2.0 / ML-DSA-87){RESET}")
    print(f"{BOLD}{CYAN}{'='*80}{RESET}\n")

    # 1. Generate Base Alpha Credentials
    print("Generating post-quantum cryptographic identity for [BASE ALPHA] (ML-DSA-87)...")
    alpha = generate_node_credentials("BASE_ALPHA", key_type="mldsa87")
    alpha_key_path = os.path.join(output_dir, "base_alpha_key.pem")
    alpha_cert_path = os.path.join(output_dir, "base_alpha_cert.pem")
    save_encrypted_credential(alpha_key_path, alpha["key_pem"].encode('utf-8'), passphrase=pw)
    with open(alpha_cert_path, "w", encoding="utf-8") as f:
        f.write(alpha["cert_pem"])
    print(f"  [OK] Base Alpha Key (AES-256-GCM): {alpha_key_path}")
    print(f"  [OK] Base Alpha Certificate:       {alpha_cert_path}")
    print(f"  [OK] Base Alpha Fingerprint:       {alpha['fingerprint'][:32]}... (SHA3-512)")

    # 2. Generate Base Bravo Credentials
    print("\nGenerating post-quantum cryptographic identity for [BASE BRAVO] (ML-DSA-87)...")
    bravo = generate_node_credentials("BASE_BRAVO", key_type="mldsa87")
    bravo_key_path = os.path.join(output_dir, "base_bravo_key.pem")
    bravo_cert_path = os.path.join(output_dir, "base_bravo_cert.pem")
    save_encrypted_credential(bravo_key_path, bravo["key_pem"].encode('utf-8'), passphrase=pw)
    with open(bravo_cert_path, "w", encoding="utf-8") as f:
        f.write(bravo["cert_pem"])
    print(f"  [OK] Base Bravo Key (AES-256-GCM): {bravo_key_path}")
    print(f"  [OK] Base Bravo Certificate:       {bravo_cert_path}")
    print(f"  [OK] Base Bravo Fingerprint:       {bravo['fingerprint'][:32]}... (SHA3-512)")

    # 3. Generate Pre-Shared Stealth Knock Token
    stealth_token = secrets.token_hex(32)
    knock_token_path = os.path.join(output_dir, "stealth_knock.key")
    save_encrypted_credential(knock_token_path, stealth_token.encode('utf-8'), passphrase=pw)
    print(f"\n  [OK] Generated Pre-Shared Stealth Knock Token (AES-256-GCM): {knock_token_path}")

    # 4. Generate Pre-Shared Whitelist Manifest
    whitelist = {
        "version": "2.0",
        "standard": "CNSA_2.0_ML_DSA_87_ZERO_TRUST",
        "description": "Authorized military peer certificate fingerprints for zero-trust P2P",
        "authorized_fingerprints": [
            alpha["fingerprint"].lower(),
            bravo["fingerprint"].lower()
        ],
        "nodes": {
            "BASE_ALPHA": {
                "fingerprint": alpha["fingerprint"].lower(),
                "cert_file": "base_alpha_cert.pem"
            },
            "BASE_BRAVO": {
                "fingerprint": bravo["fingerprint"].lower(),
                "cert_file": "base_bravo_cert.pem"
            }
        }
    }

    manifest_path = os.path.join(output_dir, "authorized_military_peers.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(whitelist, f, indent=2)

    print(f"  [OK] Exported Authorized Whitelist Manifest:   {manifest_path}")
    print(f"\n{BOLD}{GREEN}[SUCCESS] Tactical network provisioned in {output_dir}. Transfer out-of-band.{RESET}\n")

    # H27: if WE minted the ceremony passphrase into os.environ (visible in
    # /proc to the same uid for process lifetime), wipe it now that all
    # credential files are sealed. Operator-supplied passphrases (arg/env)
    # are the caller's responsibility and are left untouched.
    if minted_here and os.environ.get("P2P_TACTICAL_KEY_PW") == pw:
        try:
            # Overwrite then delete to shrink the exposure window.
            os.environ["P2P_TACTICAL_KEY_PW"] = "0" * len(pw)
        finally:
            del os.environ["P2P_TACTICAL_KEY_PW"]
        print("  [SECURE] Ephemeral ceremony passphrase wiped from process environment.")

    return whitelist


if __name__ == "__main__":
    provision_tactical_network()
