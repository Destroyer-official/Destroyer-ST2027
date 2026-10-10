
import logging
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from platform_hsm_interface import run_hardware_memory_diagnostics, get_hardware_memory_protector

# Configure logging to see output
logging.basicConfig(level=logging.CRITICAL)
logging.getLogger().setLevel(logging.CRITICAL)

logging.getLogger('platform_hsm_interface').setLevel(logging.WARNING)
logging.getLogger('pqc_algorithms').setLevel(logging.WARNING)


print("Running Hardware Security Verification...")

try:
    # 1. Initialize protector (Triggers Feature Detection)
    protector = get_hardware_memory_protector()
    print("[OK] Hardware Memory Protector initialized.")
    
    # 2. Run Diagnostics (Triggers Alloc, Wipe, Verify)
    results = run_hardware_memory_diagnostics()
    
    print("\n--- Diagnostic Results ---")
    print(f"Secure Allocation: {results.get('secure_memory_allocation')}")
    print(f"Integrity Check:   {results.get('memory_integrity_verification')}")
    print(f"Guard Pages:       {results.get('guard_page_protection')}")
    print(f"Hardware Features: {results.get('hardware_features')}")
    print(f"Wiping Success:    {results.get('cryptographic_wiping', 'N/A')}")
    
    if results.get('error_details'):
        print("\n[WARNING] Errors encountered:")
        for err in results['error_details']:
            print(f"  - {err}")
            
    if results.get('secure_memory_allocation') and results.get('memory_integrity_verification'):
        print("\n[SUCCESS] Hardware Security Verification PASSED")
    else:
        print("\n[FAILURE] Hardware Security Verification FAILED")
        exit(1)

except Exception as e:
    print(f"\n[CRITICAL FAILURE] Verification script crashed: {e}")
    import traceback
    traceback.print_exc()
    exit(1)
