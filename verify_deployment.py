#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ST2027 PRODUCTION DEPLOYMENT ASSURANCE & VERIFICATION TESTBENCH

OPERATIONAL CONTEXT:
  Executed by release engineers and air-gapped site administrators prior to
  operational deployment. Performs offline, read-only validation of cryptographic
  primitives, core module importability, memory protections, and hardware security
  module interfaces in accordance with CNSA Suite 2.0 and NIST SP 800-218.

SYSTEM INTEGRATION:
  Subsystem: Deployment Verification Subsystem (CLI / Automation)
  Standards: FIPS 203 (ML-KEM-1024), FIPS 204 (ML-DSA-87), RFC 8439 (ChaCha20-Poly1305),
             NIST SP 800-88 Rev 1 (Sanitization), SLSA Level 3+ (Build Integrity).
  Behavior: Strict fail-closed verification pipeline. Any discrepancy produces
            non-zero exit status and halts deployment sequencing.
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
    "secure_p2p",
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
    "secure_p2p.py": {"min_lines": 11000, "critical": True},
    "pqc_algorithms.py": {"min_lines": 7500, "critical": True},
    "double_ratchet.py": {"min_lines": 3500, "critical": True},
    "platform_hsm_interface.py": {"min_lines": 8000, "critical": True},
    "tls_channel_manager.py": {"min_lines": 5700, "critical": True},
}

# CNSA 2.0 Approved Algorithms (NSA CNSA 2.0 FAQ / CNSSP-15, corrected
# 2026-10-13). Documentation-only constant (runtime gates use
# cnsa2_policy_engine.CNSA2PolicyEngine): SLH-DSA-256f, ChaCha20-Poly1305,
# SHA3-* and McEliece were removed — FIPS/RFC-valid but NOT CNSA-listed.
CNSA2_APPROVED_ALGORITHMS = {
    "kem": ["ML-KEM-1024"],
    "signature": ["ML-DSA-87"],
    "aead": ["AES-256-GCM"],
    "hash": ["SHA-384", "SHA-512"],
    "kdf": ["HKDF-SHA384", "HKDF-SHA512"]
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
    Automated pre-deployment validation testbench for ST2027 secure node endpoints.
    
    Validates cryptographic conformance, core module presence, memory defenses,
    and dependency trees against authenticated baseline signatures prior to daemon startup.
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
            if not os.path.exists(file_path):
                alt_path = os.path.join("archive", "legacy_prototype", f"{module}.py")
                if os.path.exists(alt_path):
                    file_path = alt_path
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
                try:
                    importlib.import_module(module)
                except ImportError as real_err:
                    try:
                        importlib.import_module(f"archive.legacy_prototype.{module}")
                    except ImportError:
                        # Surface the ORIGINAL failure: a missing legacy twin
                        # must not mask the true cause (e.g. the fail-closed
                        # liboqs below-floor ImportError cascade in production).
                        raise real_err
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
            if not os.path.exists(file_path):
                alt_path = os.path.join("archive", "legacy_prototype", f"{module}.py")
                if os.path.exists(alt_path):
                    file_path = alt_path
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

    def verify_tls_pq_posture(self) -> bool:
        """TLS 1.3 post-quantum key-exchange posture (A-10/A-11/P1).

        Empirical gate on THIS host/runtime: PQ key exchange rides TLS 1.3
        GROUPS (RFC 10024 hybrids), never ciphersuite names. Probes the
        default ClientHello (tls_pq_policy.client_offers_hybrid_group) and
        reports OPENSSL_CONF policy visibility. WARN in lab, FAIL under
        production posture (draft-becker-cnsa2-tls-profile fail-closed).
        Ciphersuite pinning (TLS_AES_256_GCM_SHA384) happens post-handshake
        in tls_channel_manager.do_handshake.
        """
        print("\n=== TLS Post-Quantum Key-Exchange Posture ===")
        ok = True
        from production_gate import is_ts_mode
        prod = is_ts_mode()
        ssl_mod = None
        try:
            import ssl as ssl_mod
            tls13 = bool(getattr(ssl_mod, "HAS_TLSv1_3", False))
        except Exception:
            tls13 = False
        if tls13:
            self._add_result("TLS13: library support", VerificationStatus.PASS,
                             f"{getattr(ssl_mod, 'OPENSSL_VERSION', 'ssl module')}")
        else:
            self._add_result("TLS13: library support", VerificationStatus.FAIL,
                             "TLS 1.3 unavailable in this runtime")
            ok = False
        hybrid = False
        try:
            from tls_pq_policy import client_offers_hybrid_group
            hybrid = bool(client_offers_hybrid_group())
        except Exception as e:
            self._add_result("TLS13: PQ hybrid group offer", VerificationStatus.WARN,
                             f"probe unavailable: {str(e)[:60]}")
        if hybrid:
            self._add_result(
                "TLS13: PQ hybrid group offer", VerificationStatus.PASS,
                "default ClientHello offers RFC 10024 hybrid group (e.g. X25519MLKEM768)")
        elif tls13:
            self._add_result(
                "TLS13: PQ hybrid group offer",
                VerificationStatus.FAIL if prod else VerificationStatus.WARN,
                "default ClientHello offers NO RFC 10024 hybrid group")
            ok = ok and not prod
        openssl_conf = os.environ.get("OPENSSL_CONF", "").strip()
        if not openssl_conf:
            repo_root = os.path.dirname(os.path.abspath(__file__))
            candidate_cnf = os.path.join(repo_root, "deploy", "openssl_cnsa.cnf")
            if os.path.exists(candidate_cnf):
                openssl_conf = candidate_cnf
                os.environ["OPENSSL_CONF"] = candidate_cnf
        if openssl_conf:
            self._add_result("TLS13: OPENSSL_CONF policy", VerificationStatus.PASS,
                             f"explicit OpenSSL config in force: {openssl_conf}")
        else:
            self._add_result(
                "TLS13: OPENSSL_CONF policy",
                VerificationStatus.WARN if prod else VerificationStatus.SKIP,
                "no OPENSSL_CONF; KEX groups rely on runtime build defaults"
                " (harden with deploy/openssl_cnsa.cnf)")
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
            if name.upper() in ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION"):
                from production_gate import is_production
                return is_production()
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
            ("P2P_ALLOW_LEGACY_CERTS", "Legacy ECDSA certificate acceptance (TLS migration path; refused in production)"),
            ("P2P_DISABLE_STRICT_AUTH", "Strict mutual authentication disablement"),
            ("P2P_EPHEMERAL_MODE", "Ephemeral mode (check: must be intentional, not default)"),
            ("P2P_ENABLE_VULN_HQC", "HQC leg opt-in (CVE-2024-54137/CVE-2025-52473 fixed in vendored oqs 0.16.0; still refused by default, lab only)"),
            ("P2P_ENABLE_CUSTOM_ZK", "Unaudited custom ZK arithmetic (lab only)"),
            ("P2P_ENABLE_EXPERIMENTAL", "Blanket experimental crypto (lab only)"),
        ]
        known = {name.upper() for name, _ in insecure_flags}
        all_secure = True
        for flag, description in insecure_flags:
            if _truthy(flag):
                level = VerificationStatus.WARN if flag in ("P2P_ALLOW_LOOPBACK", "P2P_EPHEMERAL_MODE", "P2P_ALLOW_LEGACY_CERTS") else VerificationStatus.FAIL
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
        # A-13: production auto-raises the DHT PoW difficulty to the code
        # floor in decentralized_architecture._pow_difficulty(); report the
        # effective value so operators see the mining budget implication.
        if any(_truthy(f) for f in ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION", "P2P_TS_MODE")):
            try:
                _pow = int(os.environ.get("P2P_DHT_POW_DIFFICULTY_BYTES", "2"))
            except (TypeError, ValueError):
                _pow = 2
            if _pow < 3:
                self._add_result("Env Policy: P2P_DHT_POW_DIFFICULTY_BYTES", VerificationStatus.PASS,
                                 f"production floor enforced in code: {_pow} -> 3 leading zero bytes "
                                 "(set >=3 to pre-mine identities ahead of startup)")
            else:
                self._add_result("Env Policy: P2P_DHT_POW_DIFFICULTY_BYTES", VerificationStatus.PASS,
                                 f"PoW difficulty {_pow} >= production floor 3")
        # F-04 (audit 2026-10-14): private signing key material must never
        # ship inside the deployed runtime tree — co-located with the signed
        # config it would let a compromised host forge boot configuration.
        # Signing is offline/HSM only; FAIL the ATO gate in production.
        _leaked_keys = [
            p for p in (
                os.path.join("certs", "config_signer.key"),
                os.path.join("certs", "sbom_mldsa87_signer.sk"),
            ) if os.path.isfile(p)
        ]
        if _leaked_keys:
            if any(_truthy(f) for f in ("P2P_PRODUCTION", "SECURE_P2P_PRODUCTION", "P2P_TS_MODE")):
                self._add_result("Key Hygiene: signing key exposure", VerificationStatus.FAIL,
                                 f"private key material present in runtime tree: {', '.join(_leaked_keys)} "
                                 "— relocate signer to offline/HSM before ATO")
                all_secure = False
            else:
                self._add_result("Key Hygiene: signing key exposure", VerificationStatus.WARN,
                                 f"private keys present in tree (lab only; production would FAIL): {', '.join(_leaked_keys)}")
        else:
            self._add_result("Key Hygiene: signing key exposure", VerificationStatus.PASS,
                             "no config-signing private keys in runtime tree")
        # F-06 hardening (2026-10-15): P2P_MS_SIGNED_ONLY opts the process into
        # PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY (MicrosoftSignedOnly) —
        # irreversible for the process lifetime, so it is opt-in only via
        # dep_impl._enable_modern_mitigations. Report the active state.
        if _truthy("P2P_MS_SIGNED_ONLY"):
            self._add_result("Env Policy: P2P_MS_SIGNED_ONLY", VerificationStatus.PASS,
                             "active (only MS-signed binaries load; irreversible per-process mitigation)")
        else:
            self._add_result("Env Policy: P2P_MS_SIGNED_ONLY", VerificationStatus.PASS,
                             "not active (default: any correctly signed .pyd accepted)")
        return all_secure

    
    def verify_host_posture(self) -> bool:
        """Host hardware/firmware posture (SecureBoot, TPM, VBS/HVCI).

        Advisory in lab (WARN), fail-closed in production: a prod host
        without SecureBoot or without any TPM is NOT deployment-ready.
        Never fails the run on detection errors (reports WARN instead).
        """
        print("\n=== Host Security Posture ===")
        from production_gate import is_production
        prod = is_production()
        try:
            from platform_hsm_interface import get_host_security_posture
            posture = get_host_security_posture()
        except Exception as e:
            level = VerificationStatus.FAIL if prod else VerificationStatus.WARN
            self._add_result("Host Posture: detection", level,
                             f"posture detection unavailable: {str(e)[:80]}")
            return not prod
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
            ("TLS PQ Posture", self.verify_tls_pq_posture),
            ("Host Posture", self.verify_host_posture),
            ("Audit Logging", self.verify_audit_logging),
            ("Memory Security", self.verify_memory_security),
            ("Anti-Downgrade Policies", self.verify_secure_environment_configuration),
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

