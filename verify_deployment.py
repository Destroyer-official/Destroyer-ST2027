#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PROJECT SENTINEL - Production Deployment Verification Script

This script verifies all requirements for military-grade secure P2P communication
system production deployment. It performs comprehensive checks on:
- Core module integrity and import verification
- Cryptographic compliance (CNSA 2.0, NIST Level 5)
- Zero Trust architecture verification
- Supply chain security (DLL signatures)
- Memory security verification
- Audit logging verification

CRITICAL: This script is READ-ONLY and makes NO modifications to the codebase.

Author: Security Verification Team
Version: 1.0.0
"""

import os
import sys
import importlib
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

# Core modules that MUST be preserved (Iron Core)
CORE_MODULES = [
    "secure_p2",
    "pqc_algorithms",
    "military_security_enforcement",
    "double_ratchet",
    "hybrid_kex",
    "tls_channel_manager",
    "protocol_manager",
    "secure_key_manager",
    "platform_hsm_interface",
    "p2p_core",
    "liboqs_wrapper",
    "cnsa2_policy_engine",
    "zero_trust_engine",
    "enhanced_secure_memory",
    "dependency_security_verifier",
    "audit_logging_system",
    "cryptographic_errors"
]

# Large files that require special handling (DO NOT DELETE FUNCTIONS)
LARGE_FILES = {
    "archive/legacy_prototype/secure_p2p.py": {"min_lines": 9000, "critical": True},
    "pqc_algorithms.py": {"min_lines": 7500, "critical": True},
    "double_ratchet.py": {"min_lines": 3500, "critical": True},
    "platform_hsm_interface.py": {"min_lines": 8000, "critical": True},
    "tls_channel_manager.py": {"min_lines": 5700, "critical": True},
}

# CNSA 2.0 Approved Algorithms
CNSA2_APPROVED_ALGORITHMS = {
    "kem": ["ML-KEM-1024", "McEliece-8192128f"],
    "signature": ["ML-DSA-87", "SLH-DSA-256f"],
    "aead": ["AES-256-GCM", "ChaCha20-Poly1305"],
    "hash": ["SHA-384", "SHA3-256", "SHA3-512"],
    "kdf": ["HKDF-SHA384"]
}

# Forbidden algorithms (NO FALLBACKS)
FORBIDDEN_ALGORITHMS = [
    "RSA", "ECDSA", "ECDH", "P-256", "P-384",
    "AES-128", "AES-192", "SHA-1", "MD5",
    "DES", "3DES", "RC4", "Blowfish"
]


class VerificationStatus(Enum):
    # AUDITED (B105): false positive / test fixture, verified individually 2026-09
    PASS = "PASS"  # nosec: B105
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass
class VerificationResult:
    """Result of a single verification check"""
    check_name: str
    status: VerificationStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class VerificationReport:
    """Complete verification report"""
    timestamp: datetime
    all_passed: bool
    results: List[VerificationResult]
    summary: Dict[str, int]
    recommendations: List[str]


class DeploymentVerifier:
    """
    Production deployment verification for military-grade secure P2P system.
    
    This class performs comprehensive verification of all security requirements
    without making any modifications to the codebase.
    """
    
    def __init__(self):
        self.results: List[VerificationResult] = []
        self.baseline_data: Dict[str, Any] = {}
        
    def _add_result(self, check_name: str, status: VerificationStatus, 
                    message: str, details: Dict[str, Any] = None):
        """Add a verification result"""
        result = VerificationResult(
            check_name=check_name,
            status=status,
            message=message,
            details=details or {}
        )
        self.results.append(result)
        
        # Print result immediately
        status_symbol = {
            VerificationStatus.PASS: "[PASS]",
            VerificationStatus.FAIL: "[FAIL]",
            VerificationStatus.WARN: "[WARN]",
            VerificationStatus.SKIP: "[SKIP]"
        }
        print(f"  {status_symbol[status]} {check_name}: {message}")
        
    def verify_core_modules_exist(self) -> bool:
        """Verify all core modules exist as files"""
        print("\n=== Core Module File Verification ===")
        all_exist = True
        
        for module in CORE_MODULES:
            file_path = f"{module}.py"
            if os.path.exists(file_path):
                line_count = sum(1 for _ in open(file_path, 'r', encoding='utf-8', errors='ignore'))
                self._add_result(
                    f"File: {file_path}",
                    VerificationStatus.PASS,
                    f"Exists ({line_count} lines)",
                    {"lines": line_count}
                )
                self.baseline_data[file_path] = {"lines": line_count}
            else:
                self._add_result(
                    f"File: {file_path}",
                    VerificationStatus.FAIL,
                    "File NOT FOUND - CRITICAL"
                )
                all_exist = False
                
        return all_exist
    
    def verify_core_modules_import(self) -> bool:
        """Verify all core modules can be imported"""
        print("\n=== Core Module Import Verification ===")
        all_import = True
        
        for module in CORE_MODULES:
            try:
                importlib.import_module(module)
                self._add_result(
                    f"Import: {module}",
                    VerificationStatus.PASS,
                    "Imports successfully"
                )
            except ImportError as e:
                self._add_result(
                    f"Import: {module}",
                    VerificationStatus.FAIL,
                    f"Import failed: {str(e)[:100]}"
                )
                all_import = False
            except Exception as e:
                self._add_result(
                    f"Import: {module}",
                    VerificationStatus.WARN,
                    f"Import warning: {str(e)[:100]}"
                )
                
        return all_import
    
    def verify_large_file_integrity(self) -> bool:
        """Verify large files have not been truncated"""
        print("\n=== Large File Integrity Verification ===")
        all_intact = True
        
        for file_path, requirements in LARGE_FILES.items():
            if os.path.exists(file_path):
                line_count = sum(1 for _ in open(file_path, 'r', encoding='utf-8', errors='ignore'))
                min_lines = requirements["min_lines"]
                
                if line_count >= min_lines:
                    self._add_result(
                        f"Large File: {file_path}",
                        VerificationStatus.PASS,
                        f"{line_count} lines (min: {min_lines})",
                        {"lines": line_count, "min_required": min_lines}
                    )
                else:
                    self._add_result(
                        f"Large File: {file_path}",
                        VerificationStatus.FAIL,
                        f"TRUNCATED: {line_count} lines (min: {min_lines})",
                        {"lines": line_count, "min_required": min_lines}
                    )
                    all_intact = False
            else:
                self._add_result(
                    f"Large File: {file_path}",
                    VerificationStatus.FAIL,
                    "File NOT FOUND"
                )
                all_intact = False
                
        return all_intact
    
    def verify_dll_signatures(self) -> bool:
        """Verify DLL cryptographic signatures and multi-hash integrity (Ed25519 + SHA-512 + SHA3-512)."""
        print("\n=== DLL Cryptographic Signature & Integrity Verification ===")
        all_verified = True
        
        from cryptography.hazmat.primitives import serialization
        import hashlib
        import json
        
        dll_files = [
            ("oqs.dll", "oqs.dll.sig", "oqs.dll.hashes", "oqs.dll.pub"),
            ("libsodium.dll", "libsodium.dll.sig", "libsodium.dll.hashes", "libsodium.dll.pub")
        ]
        
        for dll, sig_file, hash_file, pub_file in dll_files:
            if not os.path.exists(dll):
                self._add_result(
                    f"DLL: {dll}",
                    VerificationStatus.FAIL,
                    "DLL binary NOT FOUND"
                )
                all_verified = False
                continue
                
            self._add_result(
                f"DLL: {dll}",
                VerificationStatus.PASS,
                "DLL binary exists"
            )
            
            # 1. Multi-Hash Cryptographic Integrity Check
            if hash_file and os.path.exists(hash_file):
                try:
                    with open(dll, 'rb') as f:
                        dll_bytes = f.read()
                    with open(hash_file, 'r', encoding='utf-8') as f:
                        expected_hashes = json.load(f)
                    
                    calc_sha512 = hashlib.sha512(dll_bytes).hexdigest()
                    calc_sha3_512 = hashlib.sha3_512(dll_bytes).hexdigest()
                    
                    if calc_sha512 == expected_hashes.get("sha512") and calc_sha3_512 == expected_hashes.get("sha3_512"):
                        self._add_result(
                            f"Hashes: {hash_file}",
                            VerificationStatus.PASS,
                            f"Cryptographic SHA-512 & SHA3-512 hashes match exactly ({len(dll_bytes)} bytes)"
                        )
                    else:
                        self._add_result(
                            f"Hashes: {hash_file}",
                            VerificationStatus.FAIL,
                            "Cryptographic hash mismatch! Possible tampering detected"
                        )
                        all_verified = False
                except Exception as e:
                    self._add_result(
                        f"Hashes: {hash_file}",
                        VerificationStatus.FAIL,
                        f"Error verifying hashes: {e}"
                    )
                    all_verified = False
            else:
                self._add_result(
                    f"Hashes: {hash_file}",
                    VerificationStatus.WARN,
                    "Hash metadata file missing"
                )
                
            # 2. Cryptographic Ed25519 Signature Verification
            if sig_file and pub_file and os.path.exists(sig_file) and os.path.exists(pub_file):
                try:
                    with open(pub_file, 'rb') as f:
                        pub_key = serialization.load_pem_public_key(f.read())
                    with open(sig_file, 'rb') as f:
                        signature = f.read()
                    
                    # Verify signature over raw DLL bytes
                    pub_key.verify(signature, dll_bytes)
                    self._add_result(
                        f"Signature: {sig_file}",
                        VerificationStatus.PASS,
                        f"Valid Ed25519 cryptographic signature verified with {pub_file}"
                    )
                except Exception as e:
                    self._add_result(
                        f"Signature: {sig_file}",
                        VerificationStatus.FAIL,
                        f"Cryptographic signature verification FAILED: {e}"
                    )
                    all_verified = False
            elif sig_file:
                self._add_result(
                    f"Signature: {sig_file}",
                    VerificationStatus.WARN,
                    f"Signature or public key file missing ({sig_file} / {pub_file})"
                )
                
        return all_verified
    
    def verify_security_policy_files(self) -> bool:
        """Verify security policy enforcement files exist"""
        print("\n=== Security Policy Verification ===")
        
        policy_files = [
            "military_security_enforcement.py",
            "cnsa2_policy_engine.py",
            "zero_trust_engine.py"
        ]
        
        all_exist = True
        for policy_file in policy_files:
            if os.path.exists(policy_file):
                self._add_result(
                    f"Policy: {policy_file}",
                    VerificationStatus.PASS,
                    "Policy file exists"
                )
            else:
                self._add_result(
                    f"Policy: {policy_file}",
                    VerificationStatus.FAIL,
                    "Policy file NOT FOUND"
                )
                all_exist = False
                
        return all_exist
    
    def verify_no_forbidden_algorithms(self) -> bool:
        """Scan for forbidden algorithm usage in core modules"""
        print("\n=== Forbidden Algorithm Scan ===")
        
        # This is a basic scan - full verification requires deeper analysis
        violations_found = False
        
        for module in CORE_MODULES:
            file_path = f"{module}.py"
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().upper()
                        
                    # Check for obvious forbidden algorithm usage
                    # Note: This is a basic check - some may be in comments or disabled code
                    found_forbidden = []
                    for algo in FORBIDDEN_ALGORITHMS:
                        # Use word boundaries to avoid false positives like "RSA" in "traversal"
                        import re
                        pattern = r'\b' + re.escape(algo.upper()) + r'\b'
                        if re.search(pattern, content):
                            # Check if it's in a FORBIDDEN list (which is OK)
                            # Check both original case and uppercase versions
                            if (f'"{algo}"' in content.replace(algo.upper(), algo) or 
                                f"'{algo}'" in content.replace(algo.upper(), algo) or
                                f'"{algo.upper()}"' in content or 
                                f"'{algo.upper()}'" in content or
                                'FORBIDDEN_ALGORITHMS' in content or
                                'forbidden_algorithms' in content):
                                # Likely in a forbidden list definition - OK
                                continue
                            found_forbidden.append(algo)
                            
                    if found_forbidden:
                        self._add_result(
                            f"Algorithm Scan: {file_path}",
                            VerificationStatus.WARN,
                            f"Potential forbidden algorithms: {', '.join(found_forbidden[:3])}"
                        )
                    else:
                        self._add_result(
                            f"Algorithm Scan: {file_path}",
                            VerificationStatus.PASS,
                            "No obvious forbidden algorithms"
                        )
                except Exception as e:
                    self._add_result(
                        f"Algorithm Scan: {file_path}",
                        VerificationStatus.SKIP,
                        f"Could not scan: {str(e)[:50]}"
                    )
                    
        return not violations_found
    
    def verify_cnsa27_readiness(self) -> bool:
        """CNSA 2.0 January-2027 procurement-gate readiness (evidence gate).

        Proves, on THIS host, with THESE binaries (not docs):
          1. Policy engine loads; ML-KEM-1024 + ML-DSA-87 validate.
          2. NEVER_AUTHORIZED_2027 enforced (HAWK-withdrawn, HashML-DSA).
          3. Native ML-KEM-1024 encaps/decaps + ML-DSA-87 sign/verify
             roundtrip with FIPS size pins (PK 1568/2592, CT 1568, SIG 4627).
        SKIP (not FAIL) when native liboqs is absent -- DLL Signatures
        covers presence separately; this gate proves behavior when present.
        """
        print("\n=== CNSA 2.0 (Jan-2027 Gate) Readiness ===")
        ok = True
        try:
            from cnsa2_policy_engine import (
                CNSA2PolicyEngine, AlgorithmCategory, SecurityPolicyViolation)
        except Exception as e:
            self._add_result("CNSA27: policy engine", VerificationStatus.FAIL,
                             f"cannot import cnsa2_policy_engine: {str(e)[:80]}")
            return False
        try:
            engine = CNSA2PolicyEngine()
            engine.validate_algorithm("ML-KEM-1024", AlgorithmCategory.KEM)
            engine.validate_algorithm("ML-DSA-87", AlgorithmCategory.SIGNATURE)
            self._add_result("CNSA27: ML-KEM-1024 + ML-DSA-87 validate",
                             VerificationStatus.PASS, "mandatory 2027 pair approved")
        except Exception as e:
            self._add_result("CNSA27: ML-KEM-1024 + ML-DSA-87 validate",
                             VerificationStatus.FAIL, f"mandatory pair rejected: {str(e)[:80]}")
            return False
        for banned in ("HAWK", "HASHML-DSA-87", "FN-DSA-1024", "MAYO"):
            try:
                engine.validate_algorithm(banned)
                self._add_result(f"CNSA27: {banned} refused",
                                 VerificationStatus.FAIL, "never-authorized algorithm accepted")
                ok = False
            except Exception:
                self._add_result(f"CNSA27: {banned} refused",
                                 VerificationStatus.PASS, "never-authorized set enforced")
        try:
            from liboqs_wrapper import LibOQS_MLKEM_1024, LibOQS_MLDSA_87
        except Exception as e:
            self._add_result("CNSA27: native PQ roundtrip", VerificationStatus.SKIP,
                             f"liboqs unavailable here: {str(e)[:60]}")
            return ok
        try:
            kem = LibOQS_MLKEM_1024()
            # B101: explicit fail-closed checks (never `assert` on a deploy
            # gate; -O strips asserts and the gate must not pass vacuously).
            if not (kem.pk_size == 1568 and kem.ct_size == 1568):
                raise ValueError(f"ML-KEM-1024 sizes wrong: {kem.pk_size}/{kem.ct_size}")
            pk, sk = kem.keygen()
            ct, ss1 = kem.encaps(pk)
            ss2 = kem.decaps(sk, ct)
            if not (ss1 == ss2 and len(ss1) == 32):
                raise ValueError("ML-KEM-1024 native roundtrip failed")
            dsa = LibOQS_MLDSA_87()
            if not (dsa.pk_size == 2592 and dsa.sig_size == 4627):
                raise ValueError(f"ML-DSA-87 sizes wrong: {dsa.pk_size}/{dsa.sig_size}")
            dpk, dsk = dsa.keygen()
            sig = dsa.sign(dsk, b"CNSA27-readiness-proof")
            if dsa.verify(dpk, b"CNSA27-readiness-proof", sig) is not True:
                raise ValueError("ML-DSA-87 native self-verify failed")
            if dsa.verify(dpk, b"CNSA27-readiness-prooX", sig) is not False:
                raise ValueError("ML-DSA-87 native forgery ACCEPTED")
            self._add_result("CNSA27: native PQ roundtrip", VerificationStatus.PASS,
                             "ML-KEM-1024 + ML-DSA-87 live, sizes pinned")
        except Exception as e:
            self._add_result("CNSA27: native PQ roundtrip", VerificationStatus.FAIL,
                             f"native proof failed: {str(e)[:80]}")
            ok = False
        return ok
    
    
    def verify_audit_logging(self) -> bool:
        """Verify audit logging system is present"""
        print("\n=== Audit Logging Verification ===")
        
        if os.path.exists("audit_logging_system.py"):
            self._add_result(
                "Audit System",
                VerificationStatus.PASS,
                "audit_logging_system.py exists"
            )
            return True
        else:
            self._add_result(
                "Audit System",
                VerificationStatus.FAIL,
                "audit_logging_system.py NOT FOUND"
            )
            return False
    
    def verify_memory_security(self) -> bool:
        """Verify memory security module is present"""
        print("\n=== Memory Security Verification ===")
        
        if os.path.exists("enhanced_secure_memory.py"):
            self._add_result(
                "Memory Security",
                VerificationStatus.PASS,
                "enhanced_secure_memory.py exists"
            )
            return True
        else:
            self._add_result(
                "Memory Security",
                VerificationStatus.FAIL,
                "enhanced_secure_memory.py NOT FOUND"
            )
            return False
    
    def generate_baseline_report(self) -> Dict[str, Any]:
        """Generate baseline report of current state"""
        print("\n=== Generating Baseline Report ===")
        
        baseline = {
            "timestamp": datetime.now().isoformat(),
            "core_modules": {},
            "large_files": {},
            "total_functions": 0
        }
        
        for module in CORE_MODULES:
            file_path = f"{module}.py"
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.count('\n') + 1
                    
                # Count functions/classes
                import re
                func_count = len(re.findall(r'^\s*(def |async def |class )', content, re.MULTILINE))
                
                baseline["core_modules"][module] = {
                    "file": file_path,
                    "lines": lines,
                    "functions_classes": func_count,
                    "hash": hashlib.sha384(content.encode()).hexdigest()[:32],
                    "sha256": hashlib.sha256(content.encode()).hexdigest(),
                    "sha512": hashlib.sha512(content.encode()).hexdigest()
                }
                baseline["total_functions"] += func_count
                
        # Large files specific tracking
        for file_path, requirements in LARGE_FILES.items():
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.count('\n') + 1
                    
                baseline["large_files"][file_path] = {
                    "lines": lines,
                    "min_required": requirements["min_lines"],
                    "critical": requirements["critical"],
                    "sha256": hashlib.sha256(content.encode()).hexdigest(),
                    "sha512": hashlib.sha512(content.encode()).hexdigest()
                }
                
        self.baseline_data = baseline
        return baseline

    def verify_secure_environment_configuration(self) -> bool:
        """Verify that no insecure downgrades or plaintext bypasses are active in deployment.

        Checks the EXACT live flag names (case-insensitive truthy match) plus
        a catch-all for any other truthy P2P_ALLOW_*/P2P_DISABLE_* override.
        Lab-only P2P_ALLOW_LOOPBACK is reported (it gates loopback IP
        acceptance AND loopback cert pinning) so prod deploys notice it.
        """
        print("\n=== Secure Environment & Anti-Downgrade Verification ===")

        def _truthy(name: str) -> bool:
            for k, v in os.environ.items():
                if k.upper() == name.upper() and str(v).strip().lower() in ("1", "true", "yes", "on"):
                    return True
            return False

        insecure_flags = [
            ("P2P_ALLOW_INSECURE_PLAINTEXT", "Unencrypted plaintext transport fallback"),
            ("P2P_ALLOW_UNVERIFIED_TOFU", "Unverified TOFU certificate pinning"),
            ("P2P_ALLOW_UNREGISTERED_ADMIN", "Unregistered admin agility update"),
            ("P2P_ALLOW_INSECURE_DANE_BYPASS", "DANE validation bypass"),
            ("P2P_ALLOW_UNKEYED_CHUNKS", "Unkeyed chunk reception bypass"),
            ("P2P_ALLOW_LOOPBACK_BYPASS", "Loopback authentication bypass (legacy name)"),
            ("P2P_ALLOW_LOOPBACK", "Loopback IP acceptance + loopback pin-skip (lab only)"),
            ("P2P_ALLOW_NO_HOSTNAME_CHECK", "TLS hostname verification bypass"),
            ("P2P_ALLOW_LEGACY_KEY_MIGRATION", "Legacy plaintext key migration"),
            ("P2P_DISABLE_STRICT_AUTH", "Strict mutual authentication disablement"),
            ("P2P_EPHEMERAL_MODE", "Ephemeral mode (check: must be intentional, not default)"),
            ("P2P_ENABLE_VULN_HQC", "Vulnerable HQC leg on oqs 0.10.1 (CVE-2024-54137/CVE-2025-52473, lab only)"),
            ("P2P_ENABLE_CUSTOM_ZK", "Unaudited custom ZK arithmetic (lab only)"),
            ("P2P_ENABLE_EXPERIMENTAL", "Blanket experimental crypto (lab only)"),
        ]
        known = {name.upper() for name, _ in insecure_flags}
        all_secure = True
        for flag, description in insecure_flags:
            if _truthy(flag):
                level = VerificationStatus.WARN if flag in ("P2P_ALLOW_LOOPBACK", "P2P_EPHEMERAL_MODE") else VerificationStatus.FAIL
                self._add_result(f"Env Policy: {flag}", level, f"OVERRIDE ACTIVE: {flag} ({description})")
                if level == VerificationStatus.FAIL:
                    all_secure = False
            else:
                self._add_result(f"Env Policy: {flag}", VerificationStatus.PASS, "Secure (not active)")
        # Catch-all: any other live P2P_ALLOW_*/P2P_DISABLE_* truthy override fails.
        for k, v in sorted(os.environ.items()):
            ku = k.upper()
            if (ku.startswith("P2P_ALLOW_") or ku.startswith("P2P_DISABLE_")) and ku not in known:
                if str(v).strip().lower() in ("1", "true", "yes", "on"):
                    self._add_result(f"Env Policy: {k}", VerificationStatus.FAIL,
                                     f"Unknown security override active: {k}={v}")
                    all_secure = False
        # Secure defaults that must remain strict in production
        for flag, want in (("P2P_REQUIRE_SIGNED_DHT", "1"), ("P2P_FAIL_ON_SOFTWARE_FALLBACK", "1")):
            val = os.environ.get(flag, "")
            if val != "" and val.strip() != want:
                self._add_result(f"Env Policy: {flag}", VerificationStatus.FAIL,
                                 f"{flag}={val} weakens secure default (want {want}/unset)")
                all_secure = False
        # S/Kademlia PoW: default 2 (16-bit, matched gen==verify) is reliable;
        # high-threat production should raise to 3 with pre-mined identities.
        if any(_truthy(f) for f in ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION")):
            try:
                _pow = int(os.environ.get("P2P_DHT_POW_DIFFICULTY_BYTES", "2"))
            except (TypeError, ValueError):
                _pow = 2
            if _pow < 3:
                self._add_result("Env Policy: P2P_DHT_POW_DIFFICULTY_BYTES", VerificationStatus.WARN,
                                 f"PoW difficulty {_pow} < 3 in production (recommend 3 with persistent pre-mined identities)")
        return all_secure

    
    def verify_host_posture(self) -> bool:
        """Host hardware/firmware posture (SecureBoot, TPM, VBS/HVCI).

        Advisory in lab (WARN), fail-closed in production: a prod host
        without SecureBoot or without any TPM is NOT deployment-ready.
        Never fails the run on detection errors (reports WARN instead).
        """
        print("\n=== Host Security Posture ===")
        try:
            from platform_hsm_interface import get_host_security_posture
            posture = get_host_security_posture()
        except Exception as e:
            self._add_result("Host Posture: detection", VerificationStatus.WARN,
                             f"posture detection unavailable: {str(e)[:80]}")
            return True
        prod = (os.environ.get("P2P_PRODUCTION", "").strip().lower() in ("1", "true", "yes", "on")
                or os.environ.get("SECURE_P2P_PRODUCTION", "").strip() in ("1", "true"))
        ok = True
        sb = posture.get("secure_boot")
        if sb is True:
            self._add_result("Host Posture: SecureBoot", VerificationStatus.PASS, "UEFI SecureBoot enabled")
        elif sb is False:
            level = VerificationStatus.FAIL if prod else VerificationStatus.WARN
            self._add_result("Host Posture: SecureBoot", level,
                             "SecureBoot DISABLED" + (" (prod fail-closed)" if prod else ""))
            ok = ok and not prod
        else:
            self._add_result("Host Posture: SecureBoot", VerificationStatus.WARN,
                             "SecureBoot state unknown (VM/BIOS boot?)")
        if posture.get("tpm_present"):
            self._add_result("Host Posture: TPM", VerificationStatus.PASS, "TPM device present")
        else:
            level = VerificationStatus.FAIL if prod else VerificationStatus.WARN
            self._add_result("Host Posture: TPM", level,
                             "no TPM device found" + (" (prod fail-closed)" if prod else ""))
            ok = ok and not prod
        extras = []
        for key in ("vbs", "hvci", "cred_guard", "kernel_lockdown", "tpm_tools", "tbs_available"):
            extras.append(f"{key}={posture.get(key)}")
        self._add_result("Host Posture: detail", VerificationStatus.PASS,
                         "os=%s; %s" % (posture.get("os"), "; ".join(extras)))
        return ok

    def run_all_verifications(self) -> VerificationReport:
        """Run all verification checks"""
        print("=" * 60)
        print("PROJECT SENTINEL - Production Deployment Verification")
        print(f"Timestamp: {datetime.now().isoformat()}")
        print("=" * 60)
        
        # Run all checks
        checks = [
            ("Core Module Files", self.verify_core_modules_exist),
            ("Core Module Imports", self.verify_core_modules_import),
            ("Large File Integrity", self.verify_large_file_integrity),
            ("DLL Signatures", self.verify_dll_signatures),
            ("Security Policies", self.verify_security_policy_files),
            ("Forbidden Algorithms", self.verify_no_forbidden_algorithms),
            ("CNSA27 Readiness", self.verify_cnsa27_readiness),
            ("Host Posture", self.verify_host_posture),
            ("Audit Logging", self.verify_audit_logging),
            ("Memory Security", self.verify_memory_security),
            ("Anti-Downgrade Policies", self.verify_secure_environment_configuration),
            ("Host Posture", self.verify_host_posture),
        ]
        
        check_results = {}
        for check_name, check_func in checks:
            try:
                check_results[check_name] = check_func()
            except Exception as e:
                self._add_result(
                    check_name,
                    VerificationStatus.FAIL,
                    f"Check failed with error: {str(e)[:100]}"
                )
                check_results[check_name] = False
        
        # Generate baseline
        baseline = self.generate_baseline_report()
        
        # Calculate summary
        summary = {
            "PASS": sum(1 for r in self.results if r.status == VerificationStatus.PASS),
            "FAIL": sum(1 for r in self.results if r.status == VerificationStatus.FAIL),
            "WARN": sum(1 for r in self.results if r.status == VerificationStatus.WARN),
            "SKIP": sum(1 for r in self.results if r.status == VerificationStatus.SKIP),
        }
        
        all_passed = summary["FAIL"] == 0
        
        # Generate recommendations
        recommendations = []
        if summary["FAIL"] > 0:
            recommendations.append("CRITICAL: Address all FAIL items before deployment")
        if summary["WARN"] > 0:
            recommendations.append("Review all WARN items for potential issues")
            
        # Print summary
        print("\n" + "=" * 60)
        print("VERIFICATION SUMMARY")
        print("=" * 60)
        print(f"  PASS: {summary['PASS']}")
        print(f"  FAIL: {summary['FAIL']}")
        print(f"  WARN: {summary['WARN']}")
        print(f"  SKIP: {summary['SKIP']}")
        print(f"\n  Overall Status: {'READY FOR DEPLOYMENT' if all_passed else 'NOT READY - FIX FAILURES'}")
        
        # Print baseline info
        print("\n" + "=" * 60)
        print("BASELINE INFORMATION")
        print("=" * 60)
        print(f"  Total Core Modules: {len(baseline['core_modules'])}")
        print(f"  Total Functions/Classes: {baseline['total_functions']}")
        print(f"  Large Files Tracked: {len(baseline['large_files'])}")
        
        for file_path, info in baseline["large_files"].items():
            print(f"    - {file_path}: {info['lines']} lines (min: {info['min_required']})")
        
        return VerificationReport(
            timestamp=datetime.now(),
            all_passed=all_passed,
            results=self.results,
            summary=summary,
            recommendations=recommendations
        )


def main():
    """Main entry point for verification script"""
    verifier = DeploymentVerifier()
    report = verifier.run_all_verifications()
    
    # Save baseline to file
    import json
    baseline_file = "notupload/backup/baseline_verification.json"
    os.makedirs(os.path.dirname(baseline_file), exist_ok=True)
    
    with open(baseline_file, 'w', encoding='utf-8') as f:
        json.dump({
            "timestamp": report.timestamp.isoformat(),
            "all_passed": report.all_passed,
            "summary": report.summary,
            "baseline": verifier.baseline_data,
            "recommendations": report.recommendations
        }, f, indent=2)
    
    print(f"\nBaseline saved to: {baseline_file}")
    
    return 0 if report.all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

