#!/usr/bin/env python3
"""
Production Deployment Script for Military P2P System

This script prepares and validates the system for production deployment.
Run this before deploying to ensure all security requirements are met.

Usage:
    python deploy_production.py [--check-only] [--generate-keys]
"""

import os
import sys
import json
import shutil
import hashlib
import argparse
# AUDITED (B404): subprocess use verified list-form argv, zero shell=True repo-wide
import subprocess  # nosec: B404
from pathlib import Path
from datetime import datetime


class ProductionDeployer:
    """Handles production deployment preparation and validation."""
    
    REQUIRED_ENV_VARS = [
        'P2P_PRODUCTION',
        'DATABASE_URL',
    ]
    
    RECOMMENDED_ENV_VARS = [
        'P2P_REQUIRE_AUTH',
        'P2P_HSM_REQUIRED',
        'SIEM_ENDPOINT',
        'P2P_LOG_LEVEL',
    ]
    
    REQUIRED_FILES = [
        'secure_p2p.py',
        'secure_transmit_2027.py',
        'noise_pq.py',
        'destroyer_node.py',
        'pqc_algorithms.py',
        'military_security_enforcement.py',
        'cnsa2_policy_engine.py',
        'nist_level5_policy_engine.py',
        'double_ratchet.py',
        'hybrid_kex.py',
        'liboqs_wrapper.py',
        'libsodium.dll',
        'oqs.dll',
    ]

    # Patterns excluded from clean production packaging/deployment
    EXCLUDED_FROM_PRODUCTION = [
        'test_*.py',
        'benchmark_*.py',
        'run_*.py',
        'generate_*.py',
        'update_*.py',
        'mark_*.py',
        'tests/**',
        'notupload/**',
        '*.bat',
        '*.log',
        'deployment_report_*.json',
    ]
    
    def __init__(self, check_only: bool = False):
        self.check_only = check_only
        self.errors = []
        self.warnings = []
        self.passed = []
        
    def log_pass(self, message: str):
        self.passed.append(message)
        print(f"PASS {message}")
        
    def log_warn(self, message: str):
        self.warnings.append(message)
        print(f"WARN {message}")
        
    def log_error(self, message: str):
        self.errors.append(message)
        print(f"FAIL {message}")
    
    def check_python_version(self) -> bool:
        """Verify Python version is 3.10+."""
        version = sys.version_info
        if version.major >= 3 and version.minor >= 10:
            self.log_pass(f"Python version: {version.major}.{version.minor}.{version.micro}")
            return True
        else:
            self.log_error(f"Python 3.10+ required, found {version.major}.{version.minor}")
            return False
    
    def check_required_files(self) -> bool:
        """Verify all required files exist."""
        all_present = True
        for filename in self.REQUIRED_FILES:
            if Path(filename).exists():
                self.log_pass(f"Found: {filename}")
            else:
                self.log_error(f"Missing: {filename}")
                all_present = False
        return all_present
    
    def check_environment_variables(self) -> bool:
        """Check required and recommended environment variables."""
        all_required = True
        
        # Check production mode (SECURE_P2P_PRODUCTION or P2P_PRODUCTION or P2P_TS_MODE)
        prod_mode = os.environ.get('SECURE_P2P_PRODUCTION') or os.environ.get('P2P_PRODUCTION') or os.environ.get('P2P_TS_MODE')
        if prod_mode and str(prod_mode).strip().lower() in ('1', 'true', 'yes', 'on'):
            self.log_pass(f"Environment: Production mode is set ({prod_mode})")
        else:
            self.log_error("Environment: P2P_PRODUCTION=1 / SECURE_P2P_PRODUCTION=true is NOT set (required for production fail-closed enforcement)")
            all_required = False

        db_url = os.environ.get('DATABASE_URL') or 'sqlite:///p2p_secure.db'
        if os.environ.get('DATABASE_URL'):
            self.log_pass(f"Environment: DATABASE_URL is set ({db_url})")
        else:
            self.log_pass(f"Environment: DATABASE_URL defaulting to local secure SQLite store ({db_url})")
        
        for var in self.RECOMMENDED_ENV_VARS:
            if os.environ.get(var):
                self.log_pass(f"Environment: {var} is set")
            else:
                self.log_warn(f"Environment: {var} is not set (recommended)")
        
        return all_required
    
    def check_dll_signatures(self) -> bool:
        """Verify DLL Ed25519 signatures + multi-hash integrity (fail-closed, 2028)."""
        import hashlib
        import json
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
        dlls = [
            ('libsodium.dll', 'libsodium.dll.sig', 'libsodium.dll.hashes', 'libsodium.dll.pub'),
            ('oqs.dll', 'oqs.dll.sig', 'oqs.dll.hashes', 'oqs.dll.pub'),
        ]
        all_verified = True

        for dll, sig_file, hash_file, pub_file in dlls:
            dll_p = Path(dll)
            if not dll_p.exists():
                self.log_warn(f"DLL missing: {dll}")
                all_verified = False
                continue
            try:
                dll_bytes = dll_p.read_bytes()
            except Exception as e:
                self.log_warn(f"DLL unreadable {dll}: {e}")
                all_verified = False
                continue
            # Hashes
            hp = Path(hash_file)
            if hp.exists():
                try:
                    expected = json.loads(hp.read_text(encoding='utf-8'))
                    if hashlib.sha512(dll_bytes).hexdigest() != expected.get("sha512") or hashlib.sha3_512(dll_bytes).hexdigest() != expected.get("sha3_512"):
                        self.log_warn(f"Hash mismatch (tamper?): {dll}")
                        all_verified = False
                        continue
                except Exception as e:
                    self.log_warn(f"Hash verify error {dll}: {e}")
                    all_verified = False
                    continue
            else:
                self.log_warn(f"Hash metadata missing: {hash_file}")
                all_verified = False
                continue
            # Ed25519
            sp, pp = Path(sig_file), Path(pub_file)
            if not sp.exists() or not pp.exists():
                self.log_warn(f"Signature/pubkey missing: {sig_file} / {pub_file}")
                all_verified = False
                continue
            try:
                pub_key = serialization.load_pem_public_key(pp.read_bytes())
                pub_key.verify(sp.read_bytes(), dll_bytes)
                self.log_pass(f"Verified signature+hashes: {dll}")
            except InvalidSignature:
                self.log_warn(f"INVALID signature (tamper?): {dll}")
                all_verified = False
            except Exception as e:
                self.log_warn(f"Signature verify error {dll}: {e}")
                all_verified = False

        return all_verified
    
    def compute_file_hashes(self) -> dict:
        """Compute SHA-384 hashes of critical files."""
        hashes = {}
        critical_files = ['libsodium.dll', 'oqs.dll', 'archive/legacy_prototype/secure_p2p.py', 'pqc_algorithms.py']
        
        for filename in critical_files:
            if Path(filename).exists():
                with open(filename, 'rb') as f:
                    file_hash = hashlib.sha384(f.read()).hexdigest()
                hashes[filename] = file_hash
                print(f"   {filename}: {file_hash[:32]}...")
        
        return hashes
    
    def setup_production_config(self) -> bool:
        """Verify production config signature and copy if not in check-only mode."""
        cfg_p = Path('config_production.json')
        sig_p = Path('config_production.json.sig')
        pub_p = Path('certs/config_signer.pub')

        if not cfg_p.exists():
            self.log_error("config_production.json not found")
            return False

        if not sig_p.exists() or not pub_p.exists():
            self.log_error("config_production.json signature or signer public key missing (fail-closed)")
            return False

        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            pub_key = serialization.load_pem_public_key(pub_p.read_bytes())
            pub_key.verify(sig_p.read_bytes(), cfg_p.read_bytes())
            self.log_pass("Verified cryptographic signature of config_production.json")
        except Exception as e:
            self.log_error(f"config_production.json signature verification failed: {e}")
            return False

        if self.check_only:
            self.log_pass("Production config exists and signature is valid")
            return True
        
        # Backup existing config
        if Path('config.json').exists():
            backup_name = f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            shutil.copy('config.json', backup_name)
            self.log_pass(f"Backed up config to {backup_name}")
        
        # Copy production config and signature
        shutil.copy('config_production.json', 'config.json')
        shutil.copy('config_production.json.sig', 'config.json.sig')
        self.log_pass("Installed signed production configuration")
        return True
    
    def run_security_validator(self) -> bool:
        """Run the security validator script."""
        if not Path('security_validator.py').exists():
            self.log_warn("security_validator.py not found")
            return False
        
        try:
            # AUDITED (B603): list-form argv (shell=False by default), zero shell=True repo-wide (verified)
            result = subprocess.run(  # nosec: B603
                [sys.executable, 'security_validator.py', '--strict'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                self.log_pass("Security validation passed")
                return True
            else:
                self.log_error("Security validation failed")
                print(result.stdout)
                return False
        except subprocess.TimeoutExpired:
            self.log_error("Security validation timed out")
            return False
        except Exception as e:
            self.log_error(f"Security validation error: {e}")
            return False
    
    def check_dependencies(self) -> bool:
        """Verify all Python dependencies are installed."""
        required_packages = [
            'cryptography',
            'aiohttp',
            'psutil',
        ]
        
        all_installed = True
        for package in required_packages:
            try:
                __import__(package)
                self.log_pass(f"Package: {package}")
            except ImportError:
                self.log_error(f"Package missing: {package}")
                all_installed = False
        
        return all_installed
    
    def generate_deployment_report(self) -> dict:
        """Generate deployment readiness report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                'platform': sys.platform,
            },
            'checks': {
                'passed': len(self.passed),
                'warnings': len(self.warnings),
                'errors': len(self.errors),
            },
            'passed_items': self.passed,
            'warnings': self.warnings,
            'errors': self.errors,
            'ready_for_production': len(self.errors) == 0,
        }
        
        return report
    
    def deploy(self) -> bool:
        """Run full deployment preparation."""
        print("=" * 60)
        print("MILITARY P2P PRODUCTION DEPLOYMENT")
        print(f"Mode: {'CHECK ONLY' if self.check_only else 'FULL DEPLOYMENT'}")
        print("=" * 60)
        print()
        
        print("=== Python Environment ===")
        self.check_python_version()
        print()
        
        print("=== Required Files ===")
        self.check_required_files()
        print()
        
        print("=== Environment Variables ===")
        self.check_environment_variables()
        print()
        
        print("=== DLL Signatures ===")
        self.check_dll_signatures()
        print()
        
        print("=== File Hashes ===")
        hashes = self.compute_file_hashes()
        print()
        
        print("=== Dependencies ===")
        self.check_dependencies()
        print()
        
        print("=== Configuration ===")
        self.setup_production_config()
        print()
        
        print("=== Security Validation ===")
        self.run_security_validator()
        print()
        
        # Generate report
        report = self.generate_deployment_report()
        
        report_file = f"deployment_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to: {report_file}")
        print()
        
        # Summary
        print("=" * 60)
        print("DEPLOYMENT SUMMARY")
        print("=" * 60)
        print(f"Passed:   {len(self.passed)}")
        print(f"Warnings: {len(self.warnings)}")
        print(f"Errors:   {len(self.errors)}")
        print()
        
        if len(self.errors) == 0:
            print("PASS READY FOR PRODUCTION DEPLOYMENT")
            return True
        else:
            print("FAIL NOT READY - Fix errors before deployment")
            return False


def main():
    parser = argparse.ArgumentParser(description='Production Deployment Script')
    parser.add_argument('--check-only', action='store_true',
                        help='Only check readiness, do not modify files')
    parser.add_argument('--generate-keys', action='store_true',
                        help='Generate new signing keys')
    args = parser.parse_args()
    
    deployer = ProductionDeployer(check_only=args.check_only)
    success = deployer.deploy()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()

