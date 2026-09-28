import os
import hashlib
import json
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def _write_new_private(path: Path, data: bytes) -> None:
    """Create a new file with 0600 from the first byte (no chmod race)."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
    except BaseException:
        try:
            os.unlink(str(path))
        # AUDITED (B110): intentional best-effort cleanup/probe fallback; no security decision swallowed (triaged 2026-09 waves)
        except Exception:  # nosec: B110
            pass
        raise

def generate_military_ca_keys(passphrase: Optional[bytes] = None, force_overwrite: bool = False):
    """Generates or loads Military CA keypair with passphrase encryption (Item 48 / Finding 7.3)."""
    ca_key_file = Path("military_root_ca.pem")
    pub_key_file = Path("oqs.dll.pub")

    if ca_key_file.exists() and not force_overwrite:
        print(f"[SECURITY] Existing CA key found at {ca_key_file}. Refusing unconditional overwrite.")
        env_pass = os.environ.get("P2P_CA_PASSPHRASE", "").encode('utf-8')
        used_pass = passphrase or (env_pass if env_pass else None)
        try:
            with open(ca_key_file, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=used_pass)
        except Exception as e:
            print(f"[WARN] Could not decrypt existing CA key without valid passphrase: {e}")
            print("Set P2P_CA_PASSPHRASE environment variable or pass force_overwrite=True.")
            raise

    print("Generating Military CA Root Keys (Ed25519)...")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Require passphrase encryption for CA private key (Item 48).
    # The passphrase is NEVER printed: without an explicit secret the tool
    # writes a generated custodian secret to a 0400 sidecar and prints only
    # its path. Existing keys are never overwritten without force_overwrite.
    env_pass = os.environ.get("P2P_CA_PASSPHRASE", "")
    if passphrase:
        ca_passphrase = passphrase
    elif env_pass:
        ca_passphrase = env_pass.encode('utf-8')
    else:
        import secrets
        generated_secret = secrets.token_urlsafe(32)
        sidecar = Path("military_root_ca.passphrase")
        try:
            fd = os.open(str(sidecar), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            with os.fdopen(fd, 'w') as f:
                f.write(generated_secret)
        except FileExistsError:
            raise RuntimeError(
                "Refusing to mint a CA key: no P2P_CA_PASSPHRASE and "
                "military_root_ca.passphrase already exists")
        print("[SECURITY] No P2P_CA_PASSPHRASE provided. Generated custodian "
              f"secret stored at {sidecar} (mode 0400). It is NOT printed.")
        ca_passphrase = generated_secret.encode('utf-8')

    _write_new_private(ca_key_file, private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(ca_passphrase)
    ))

    # Save Public Key (Distributed with app). Never silently replace an
    # existing trust anchor with different bytes.
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if pub_key_file.exists():
        existing = pub_key_file.read_bytes()
        if existing != pub_bytes:
            raise RuntimeError(
                f"Refusing to overwrite {pub_key_file} with a different public "
                "key (trust-anchor replacement). Pass force_overwrite=True "
                "through an explicit ceremony if rotation is intended.")
    else:
        with open(pub_key_file, "wb") as f:
            f.write(pub_bytes)
    
    print("[OK] Encrypted CA Root Keys generated successfully.")
    return private_key

def sign_dll(dll_path, private_key):
    """Signs the DLL and generates integrity hashes."""
    print(f"Signing {dll_path}...")
    
    with open(dll_path, "rb") as f:
        data = f.read()

    # 1. Generate Cryptographic Signature
    signature = private_key.sign(data)

    with open(f"{dll_path}.sig", "wb") as f:
        f.write(signature)
    print(f"[OK] Signature created: {dll_path}.sig")

    # 2. Generate Hash Manifest (SHA2-512, SHA3-512)
    manifest = {
        "sha512": hashlib.sha512(data).hexdigest(),
        "sha3_512": hashlib.sha3_512(data).hexdigest(), # NIST FIPS 202
        "size": len(data)
    }
    
    with open(f"{dll_path}.hashes", "w") as f:
        json.dump(manifest, f, indent=4)
    print(f"[OK] Integrity manifest created: {dll_path}.hashes")

if __name__ == "__main__":
    if not os.path.exists("oqs.dll"):
        print("[ERROR] oqs.dll not found in current directory.")
        exit(1)

    key = generate_military_ca_keys()
    sign_dll("oqs.dll", key)
    print("\n[SUCCESS] Supply chain security established for oqs.dll")
    
    if os.path.exists("libsodium.dll"):
        sign_dll("libsodium.dll", key)
        print("\n[SUCCESS] Supply chain security established for libsodium.dll")

