import os
import py_compile
import sys

files = [
    'archive/legacy_prototype/secure_p2.py',
    'archive/legacy_prototype/secure_p2p.py',
    'nc3_nuclear_command.py',
    'pqc_algorithms.py',
    'ca_services.py',
    'double_ratchet.py',
    'hybrid_kex.py',
    'tls_channel_manager.py',
    'secure_memory_wiper.py',
    'cnsa2_policy_engine.py'
]

print(f"{'File':<25} {'Lines':>8} {'Bytes':>12} {'Syntax'}")
print("-" * 55)

all_passed = True
for filename in files:
    if not os.path.exists(filename):
        print(f"{filename:<25} {'MISSING':>8}")
        all_passed = False
        continue
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        lines = len(f.readlines())
    size = os.path.getsize(filename)
    try:
        py_compile.compile(filename, doraise=True)
        syntax = "PASS (OK)"
    except Exception as e:
        syntax = f"FAIL ({e})"
        all_passed = False
    print(f"{filename:<25} {lines:>8d} {size:>12d} {syntax}")

print("-" * 55)
if all_passed:
    print("ALL CORE FILES PRESENT, SYNTAX VERIFIED, AND COMPILED SUCCESSFULLY.")
else:
    print("WARNING: ONE OR MORE FILES FAILED VERIFICATION.")
    sys.exit(1)
