#!/usr/bin/env python3
"""
Military Security Validator

Pre-deployment security validation script for the military-grade P2P messaging system.
Validates cryptographic algorithms, security configurations, and compliance requirements.

Usage:
    python security_validator.py [--strict] [--report]
"""

import sys
import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger(__name__)

class SecurityValidator:
    """Validates security configuration and compliance for military deployment."""
    
    # CNSA 2.0 Approved Algorithms
    APPROVED_KEM = {'ML-KEM-1024', 'McEliece-8192128f'}
    APPROVED_SIG = {'ML-DSA-87', 'SLH-DSA-256f', 'FALCON-1024'}
    APPROVED_AEAD = {'AES-256-GCM', 'ChaCha20-Poly1305'}
    APPROVED_HASH = {'SHA-384', 'SHA3-512', 'SHA-512'}
    APPROVED_KDF = {'HKDF-SHA384', 'HKDF-SHA512'}
    
    # Forbidden Algorithms
    FORBIDDEN = {
        'RSA', 'DSA', 'ECDSA', 'DH', 'ECDHE',
        'AES-128', 'AES-192', 'SHA-1', 'SHA-256', 'MD5',
        'RC4', 'DES', '3DES', 'ML-KEM-512', 'ML-KEM-768'
    }
    
    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode
        self.results: List[Dict[str, Any]] = []
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        
    def check(self, name: str, condition: bool, message: str, critical: bool = False) -> bool:
        """Record a security check result."""
        status = "PASS" if condition else ("FAIL" if critical else "WARN")
        
        result = {
            'name': name,
            'status': status,
            'message': message,
            'critical': critical,
            'timestamp': datetime.now().isoformat()
        }
        self.results.append(result)
        
        if condition:
            self.passed += 1
            log.info(f"[PASS] {name}: {message}")
        elif critical:
            self.failed += 1
            log.error(f"[FAIL] {name}: {message}")
        else:
            self.warnings += 1
            log.warning(f"[WARN] {name}: {message}")
            
        return condition
    
    def validate_config(self) -> bool:
        """Validate security configuration."""
        log.info("\n=== Configuration Validation ===")
        
        config_path = Path('config.json')
        if not config_path.exists():
            return self.check("Config File", False, "config.json not found", critical=True)
        
        try:
            with open(config_path) as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            return self.check("Config Parse", False, f"Invalid JSON: {e}", critical=True)
        
        # Check security level
        security_level = config.get('security_level') or config.get('security', {}).get('level', '')
        self.check("Security Level", security_level == "MAXIMUM", 
                   f"Security level is {security_level}", critical=True)
        
        # Check quantum resistance
        qr_enabled = (
            config.get('compliance', {}).get('cnsa_2_0', False)
            or config.get('security', {}).get('quantum_resistance', {}).get('enabled', False)
            or (config.get('cryptography', {}).get('algorithms', {}).get('kem') == 'ML-KEM-1024')
        )
        self.check("Quantum Resistance", qr_enabled,
                   "Quantum resistance enabled", critical=True)
        
        # Check TLS version
        tls = config.get('networking', {}).get('tls', {}) or config.get('network', {}).get('tls', {})
        tls_min = tls.get('min_version', '1.3')
        self.check("TLS Version", tls_min == "1.3",
                   f"TLS minimum version: {tls_min}", critical=True)
        
        # Check no plaintext fallback
        allow_fallback = tls.get('allow_plaintext_fallback', False)
        self.check("No Plaintext Fallback", 
                   not allow_fallback,
                   "Plaintext fallback disabled", critical=True)
        
        # Check memory protection
        mem_enabled = (
            config.get('security', {}).get('enable_memory_protection', False)
            or config.get('security', {}).get('memory_protection', {}).get('enabled', False)
        )
        self.check("Memory Protection", mem_enabled,
                   "Memory protection enabled", critical=True)
        
        # Check for exposed credentials
        db_url = config.get('database', {}).get('url', '')
        has_credentials = '@' in db_url and not db_url.startswith('${')
        self.check("No Exposed Credentials", not has_credentials,
                   "Database credentials should use environment variables", critical=self.strict_mode)
        
        return self.failed == 0
    
    def validate_algorithms(self) -> bool:
        """Validate cryptographic algorithm compliance."""
        log.info("\n=== Algorithm Validation ===")
        
        try:
            from pqc_algorithms import (
                EnhancedMLKEM_1024, EnhancedFALCON_1024,
                MILITARY_ENFORCEMENT_ACTIVE
            )
            
            self.check("Military Enforcement", MILITARY_ENFORCEMENT_ACTIVE,
                       "Military security enforcement active", critical=True)
            
            # Test ML-KEM-1024
            try:
                kem = EnhancedMLKEM_1024()
                pk, sk = kem.keygen()
                ct, ss1 = kem.encaps(pk)
                ss2 = kem.decaps(sk, ct)
                self.check("ML-KEM-1024", ss1 == ss2,
                           f"KEM functional (pk={len(pk)}, ct={len(ct)}, ss={len(ss1)})", critical=True)
            except Exception as e:
                self.check("ML-KEM-1024", False, f"KEM failed: {e}", critical=True)
            
            # Test Signatures
            try:
                sig = EnhancedFALCON_1024()
                pk, sk = sig.keygen()
                message = b"Test message for signature validation"
                signature = sig.sign(sk, message)
                valid = sig.verify(pk, message, signature)
                self.check("Hybrid Signatures", valid,
                           "Signature scheme functional", critical=True)
            except Exception as e:
                self.check("Hybrid Signatures", False, f"Signature failed: {e}", critical=True)
                
        except ImportError as e:
            self.check("PQC Import", False, f"Failed to import PQC: {e}", critical=True)
            return False
        
        return self.failed == 0
    
    def validate_dependencies(self) -> bool:
        """Validate security-critical dependencies."""
        log.info("\n=== Dependency Validation ===")
        
        # Check libsodium
        libsodium_path = Path('libsodium.dll')
        self.check("libsodium.dll", libsodium_path.exists(),
                   "libsodium.dll present", critical=True)
        
        # Check liboqs
        oqs_path = Path('oqs.dll')
        self.check("oqs.dll", oqs_path.exists(),
                   "oqs.dll present", critical=True)
        
        # Verify DLL hashes (add your verified hashes here)
        if oqs_path.exists():
            with open(oqs_path, 'rb') as f:
                oqs_hash = hashlib.sha256(f.read()).hexdigest()
            log.info(f"   oqs.dll SHA256: {oqs_hash}")
        
        # Check signature files
        oqs_sig = Path('oqs.dll.sig')
        self.check("DLL Signature", oqs_sig.exists(),
                   "oqs.dll signature file present", critical=self.strict_mode)
        
        return self.failed == 0
    
    def validate_memory_protection(self) -> bool:
        """Validate memory protection features."""
        log.info("\n=== Memory Protection Validation ===")
        
        try:
            from enhanced_secure_memory import (
                get_enhanced_memory_manager,
                SecurityLevel
            )
            
            manager = get_enhanced_memory_manager()
            self.check("Memory Manager", manager is not None,
                       "Secure memory manager initialized", critical=True)
            
        except ImportError as e:
            self.check("Memory Manager Import", False, 
                       f"Failed to import: {e}", critical=True)
            return False
        
        return self.failed == 0
    
    def validate_tls(self) -> bool:
        """Validate TLS configuration."""
        log.info("\n=== TLS Validation ===")
        
        try:
            import ssl
            
            # Check TLS 1.3 support
            has_tls13 = hasattr(ssl, 'TLSVersion') and hasattr(ssl.TLSVersion, 'TLSv1_3')
            self.check("TLS 1.3 Support", has_tls13,
                       "TLS 1.3 available in Python SSL", critical=True)
            
            # Check post-quantum TLS support
            try:
                from tls_channel_manager import TLSSecureChannel
                self.check("PQ-TLS Module", True,
                           "Post-quantum TLS module available", critical=True)
            except ImportError:
                self.check("PQ-TLS Module", False,
                           "Post-quantum TLS module not available", critical=True)
                
        except Exception as e:
            self.check("TLS Validation", False, f"Error: {e}", critical=True)
            return False
        
        return self.failed == 0
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate security validation report."""
        return {
            'timestamp': datetime.now().isoformat(),
            'mode': 'strict' if self.strict_mode else 'standard',
            'summary': {
                'passed': self.passed,
                'failed': self.failed,
                'warnings': self.warnings,
                'total': len(self.results),
                'compliance': self.failed == 0
            },
            'results': self.results
        }
    
    def run_all_validations(self) -> bool:
        """Run all security validations."""
        log.info("=" * 60)
        log.info("MILITARY SECURITY VALIDATION")
        log.info(f"Mode: {'STRICT' if self.strict_mode else 'STANDARD'}")
        log.info("=" * 60)
        
        self.validate_config()
        self.validate_algorithms()
        self.validate_dependencies()
        self.validate_memory_protection()
        self.validate_tls()
        
        log.info("\n" + "=" * 60)
        log.info("VALIDATION SUMMARY")
        log.info("=" * 60)
        log.info(f"Passed:   {self.passed}")
        log.info(f"Failed:   {self.failed}")
        log.info(f"Warnings: {self.warnings}")
        log.info("=" * 60)
        
        if self.failed == 0:
            log.info("[PASS] SECURITY VALIDATION PASSED")
            return True
        else:
            log.error("[FAIL] SECURITY VALIDATION FAILED")
            return False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Military Security Validator')
    parser.add_argument('--strict', action='store_true', 
                        help='Enable strict validation mode')
    parser.add_argument('--report', action='store_true',
                        help='Generate JSON report')
    args = parser.parse_args()
    
    validator = SecurityValidator(strict_mode=args.strict)
    success = validator.run_all_validations()
    
    if args.report:
        report = validator.generate_report()
        report_path = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        log.info(f"Report saved to: {report_path}")
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
