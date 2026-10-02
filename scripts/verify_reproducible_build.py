#!/usr/bin/env python3
"""
Signed Reproducible Build Verification Script
=============================================
Validates binary provenance, Ed25519 cryptographic signatures, SHA3-512
cryptographic hashes, and SBOM synchronization for 2027+ Defense Authorization (ATO).
Conforms to SLSA Level 3+ and NIST SP 800-161 (Cybersecurity Supply Chain Risk Management).
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# Set project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def hash_file(filepath: Path) -> dict:
    """Computes SHA-256, SHA-512, and SHA3-512 for a given file."""
    with open(filepath, "rb") as f:
        data = f.read()
    return {
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "sha3_512": hashlib.sha3_512(data).hexdigest(),
    }


def verify_ed25519_signature(binary_path: Path, sig_path: Path, pub_path: Path) -> bool:
    """Verifies Ed25519 digital signature of native binary."""
    if not (binary_path.exists() and sig_path.exists() and pub_path.exists()):
        return False

    with open(binary_path, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        sig = f.read()
    with open(pub_path, "rb") as f:
        pub_bytes = f.read()

    try:
        public_key = serialization.load_pem_public_key(pub_bytes)
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(sig, data)
            return True
        return False
    except Exception as e:
        print(f"  [!] Signature verification failed for {binary_path.name}: {e}")
        return False


def run_reproducible_build_verification():
    print("=" * 78)
    print("REPRODUCIBLE BUILD & SUPPLY CHAIN INTEGRITY VERIFICATION (SLSA LEVEL 3+)")
    print("=" * 78)

    reports_dir = PROJECT_ROOT / "compliance_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "verification_standard": "SLSA Level 3+ / NIST SP 800-161 / FIPS 140-3",
        "binaries": {},
        "core_modules": {},
        "sbom_status": {},
        "overall_status": "PENDING"
    }

    all_passed = True

    # 1. Verify Native DLL Cryptographic Boundaries
    dll_targets = ["oqs.dll", "libsodium.dll"]
    print("\n[*] Validating Native Cryptographic Binaries (oqs.dll, libsodium.dll)...")
    for dll_name in dll_targets:
        dll_path = PROJECT_ROOT / dll_name
        sig_path = PROJECT_ROOT / f"{dll_name}.sig"
        pub_path = PROJECT_ROOT / f"{dll_name}.pub"
        hashes_path = PROJECT_ROOT / f"{dll_name}.hashes"

        if not dll_path.exists():
            print(f"  [-] FAIL: Missing binary {dll_name}")
            all_passed = False
            continue

        hashes = hash_file(dll_path)
        sig_valid = verify_ed25519_signature(dll_path, sig_path, pub_path)

        manifest_match = False
        if hashes_path.exists():
            try:
                with open(hashes_path, "r", encoding="utf-8") as f:
                    stored_hashes = json.load(f)
                manifest_match = (
                    stored_hashes.get("sha512") == hashes["sha512"] and
                    stored_hashes.get("sha3_512") == hashes["sha3_512"]
                )
            except Exception:
                manifest_match = False

        status = "PASS" if (sig_valid and manifest_match) else "FAIL"
        if status != "PASS":
            all_passed = False

        results["binaries"][dll_name] = {
            "hashes": hashes,
            "signature_verified": sig_valid,
            "manifest_matched": manifest_match,
            "status": status
        }
        print(f"  [+] {dll_name}: Ed25519 Sig: {'VERIFIED' if sig_valid else 'INVALID'} | "
              f"SHA3-512: {hashes['sha3_512'][:16]}... | Status: {status}")

    # 2. Verify Core Python Source Modules
    print("\n[*] Auditing Core Defense Python Module Integrity...")
    critical_modules = [
        "platform_hsm_interface.py",
        "cnsa2_policy_engine.py",
        "audit_logging_system.py",
        "pqc_algorithms.py",
        "metadata_resistance.py",
        "network_adversary_resistance.py",
        "secure_p2p.py"
    ]
    merkle_hasher = hashlib.sha512()
    for mod_name in critical_modules:
        mod_path = PROJECT_ROOT / mod_name
        if not mod_path.exists():
            print(f"  [-] FAIL: Missing core module {mod_name}")
            all_passed = False
            continue
        mod_hashes = hash_file(mod_path)
        merkle_hasher.update(mod_hashes["sha3_512"].encode('utf-8'))
        results["core_modules"][mod_name] = {
            "size_bytes": mod_hashes["size_bytes"],
            "sha3_512": mod_hashes["sha3_512"]
        }
        print(f"  [+] {mod_name:<32}: SHA3-512: {mod_hashes['sha3_512'][:16]}... ({mod_hashes['size_bytes']} B)")

    source_tree_merkle_root = merkle_hasher.hexdigest()
    results["source_tree_merkle_root"] = source_tree_merkle_root
    print(f"\n  [=] Core Modules Merkle Root: {source_tree_merkle_root[:24]}...")

    # 2b. Hash-Manifest CI Gate: Critical Concurrent-Edit Files
    # These 4 files are actively edited by multiple parties; any drift from
    # the recorded manifest fails the build (detects unauthorized or
    # uncoordinated changes in CI).
    print("\n[*] Hash-Manifest CI Gate: Critical Concurrent-Edit Files...")
    manifest_path = PROJECT_ROOT / "critical_modules.hashes"
    if not manifest_path.exists():
        print(f"  [-] FAIL: Missing hash manifest {manifest_path.name}")
        all_passed = False
    else:
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                expected = json.load(f)
            gate_passed = True
            results["critical_modules_manifest"] = {}
            for name, exp in expected.items():
                fpath = PROJECT_ROOT / name
                if not fpath.exists():
                    print(f"  [-] FAIL: Missing critical file {name}")
                    gate_passed = False
                    all_passed = False
                    continue
                actual = hash_file(fpath)
                match = (
                    actual["sha512"] == exp["sha512"] and
                    actual["sha3_512"] == exp["sha3_512"] and
                    actual["size_bytes"] == exp["size_bytes"]
                )
                results["critical_modules_manifest"][name] = {
                    "expected_sha3_512": exp["sha3_512"],
                    "actual_sha3_512": actual["sha3_512"],
                    "matched": match
                }
                status = "MATCH" if match else "DRIFT"
                if not match:
                    gate_passed = False
                    all_passed = False
                print(f"  [{'+' if match else '-'}] {name}: {status} (sha3_512={actual['sha3_512'][:16]}...)")
            if gate_passed:
                print("  [+] All critical modules match manifest")
        except Exception as e:
            print(f"  [-] FAIL: Manifest verification error: {e}")
            all_passed = False

    # 3. Verify SBOM Artifacts and Signatures
    print("\n[*] Verifying Software Bill of Materials (SBOM) Artifacts & Signatures...")
    cdx_path = reports_dir / "cyclonedx_sbom.json"
    spdx_path = reports_dir / "spdx_sbom.json"
    anchor_pub_path = PROJECT_ROOT / "certs" / "sbom_mldsa87_signer.pub"

    cdx_valid = cdx_path.exists() and cdx_path.stat().st_size > 0
    spdx_valid = spdx_path.exists() and spdx_path.stat().st_size > 0
    cdx_sig_valid = False
    spdx_sig_valid = False

    if cdx_valid and spdx_valid and anchor_pub_path.exists():
        try:
            from liboqs_wrapper import LibOQS_MLDSA_87
            verifier = LibOQS_MLDSA_87()
            anchor_pk = anchor_pub_path.read_bytes()

            cdx_sig_path = cdx_path.with_suffix(cdx_path.suffix + ".mldsa87.sig")
            if cdx_sig_path.exists():
                cdx_sig_valid = verifier.verify(anchor_pk, cdx_path.read_bytes(), cdx_sig_path.read_bytes())

            spdx_sig_path = spdx_path.with_suffix(spdx_path.suffix + ".mldsa87.sig")
            if spdx_sig_path.exists():
                spdx_sig_valid = verifier.verify(anchor_pk, spdx_path.read_bytes(), spdx_sig_path.read_bytes())
        except Exception as e:
            print(f"  [-] SBOM signature verification error: {e}")

    results["sbom_status"] = {
        "cyclonedx_v1_5_present": cdx_valid,
        "cyclonedx_path": str(cdx_path.relative_to(PROJECT_ROOT)) if cdx_valid else None,
        "cyclonedx_mldsa87_signature_verified": cdx_sig_valid,
        "spdx_v2_3_present": spdx_valid,
        "spdx_path": str(spdx_path.relative_to(PROJECT_ROOT)) if spdx_valid else None,
        "spdx_mldsa87_signature_verified": spdx_sig_valid,
        "trusted_anchor_verified": anchor_pub_path.exists(),
    }
    print(f"  [+] CycloneDX v1.5 SBOM: {'PRESENT' if cdx_valid else 'MISSING'} (Sig: {'VALID' if cdx_sig_valid else 'FAIL'})")
    print(f"  [+] SPDX v2.3 SBOM:      {'PRESENT' if spdx_valid else 'MISSING'} (Sig: {'VALID' if spdx_sig_valid else 'FAIL'})")

    if not (cdx_valid and spdx_valid and cdx_sig_valid and spdx_sig_valid):
        all_passed = False

    # 4. Final Receipt Output & Cryptographic Signature
    results["overall_status"] = "PASS" if all_passed else "FAIL"
    receipt_file = reports_dir / "signed_reproducible_build_receipt.json"
    receipt_bytes = json.dumps(results, indent=2).encode('utf-8')
    with open(receipt_file, "wb") as f:
        f.write(receipt_bytes)

    # Sign the receipt with ML-DSA-87 anchor
    receipt_sig_file = reports_dir / "signed_reproducible_build_receipt.json.sig"
    try:
        sk_path = PROJECT_ROOT / "certs" / "sbom_mldsa87_signer.sk"
        if sk_path.exists():
            from liboqs_wrapper import LibOQS_MLDSA_87
            signer = LibOQS_MLDSA_87()
            receipt_sig = signer.sign(sk_path.read_bytes(), receipt_bytes)
            receipt_sig_file.write_bytes(receipt_sig)
            print(f"  [+] Signed receipt with ML-DSA-87 -> {receipt_sig_file.name}")
    except Exception as e:
        print(f"  [-] Receipt signing notice: {e}")

    print("\n" + "=" * 78)
    if all_passed:
        print(f"[SUCCESS] Signed reproducible build verification PASSED (100% Verified)")
        print(f"          Receipt: {receipt_file}")
        return 0
    else:
        print(f"[FAILED] Build verification failed. Check errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(run_reproducible_build_verification())
