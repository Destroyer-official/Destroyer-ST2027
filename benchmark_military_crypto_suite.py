#!/usr/bin/env python3
"""
================================================================================
  DEPARTMENT OF DEFENSE // STRATEGIC COMMUNICATIONS COMMAND
  HIGH-PRECISION MILITARY CRYPTOGRAPHIC PERFORMANCE & THROUGHPUT BENCHMARK
  STANDARDS: NIST FIPS 203 / 204 / 205 / CNSA 2.0 / RFC 8439 / FIPS 197
================================================================================
Benchmark Battery:
  1. Post-Quantum KEM & DSS Operations Latency (ML-KEM-1024, McEliece, ML-DSA, SLH-DSA, Falcon vs X25519/Ed25519)
  2. Symmetric AEAD Bulk Cipher Throughput (AES-256-GCM vs ChaCha20-Poly1305 across 64B -> 10MB)
  3. Post-Quantum Double Ratchet Stepping & Message Pipeline Latency
  4. Network Handshake Bandwidth Wire Footprint & Round-Trip Overhead
================================================================================
"""

import os
import sys
import time
import secrets
import statistics
from typing import Dict, List, Tuple, Any

# Ensure workspace imports are prioritized
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from liboqs_wrapper import (
    LibOQS_MLKEM_1024,
    LibOQS_McEliece_8192128f,
    LibOQS_MLDSA_87,
    LibOQS_SLH_DSA_256f,
    LibOQS_Falcon_1024,
    HybridKEM,
    HybridSignature
)
from double_ratchet import DoubleRatchet

# ANSI colors
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"

def print_section(title: str):
    print(f"\n{BOLD}{CYAN}{'='*80}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*80}{RESET}")

# ==============================================================================
# BENCHMARK 1: PQC ASYMMETRIC vs CLASSICAL ALGORITHMS LATENCY
# ==============================================================================
def benchmark_asymmetric_primitives(trials: int = 15):
    print_section("STAGE 1: POST-QUANTUM vs CLASSICAL ASYMMETRIC LATENCY BENCHMARK")
    print(f"Executing {trials} independent trials per cryptographic operation...\n")

    results = []

    # --- 1.1 Classical X25519 ---
    keygen_times, encaps_times, decaps_times = [], [], []
    for _ in range(trials):
        t0 = time.perf_counter()
        priv_a = x25519.X25519PrivateKey.generate()
        pub_a = priv_a.public_key()
        keygen_times.append((time.perf_counter() - t0) * 1000)

        priv_b = x25519.X25519PrivateKey.generate()
        pub_b = priv_b.public_key()

        t0 = time.perf_counter()
        ss_a = priv_a.exchange(pub_b)
        encaps_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        ss_b = priv_b.exchange(pub_a)
        decaps_times.append((time.perf_counter() - t0) * 1000)

    results.append({
        "Algorithm": "Classical X25519 (ECDH)",
        "Type": "Key Agreement",
        "Security": "128-bit (Broken by Shor)",
        "Keygen (ms)": statistics.mean(keygen_times),
        "Encaps/Sign (ms)": statistics.mean(encaps_times),
        "Decaps/Verify (ms)": statistics.mean(decaps_times),
        "PK Size (B)": 32,
        "CT/Sig Size (B)": 32
    })

    # --- 1.2 Classical Ed25519 ---
    keygen_times, sign_times, verify_times = [], [], []
    test_msg = b"TOP-SECRET TACTICAL MILITARY ACTION MESSAGE DEFCON-1"
    for _ in range(trials):
        t0 = time.perf_counter()
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        keygen_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        sig = priv.sign(test_msg)
        sign_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        pub.verify(sig, test_msg)
        verify_times.append((time.perf_counter() - t0) * 1000)

    results.append({
        "Algorithm": "Classical Ed25519",
        "Type": "Digital Signature",
        "Security": "128-bit (Broken by Shor)",
        "Keygen (ms)": statistics.mean(keygen_times),
        "Encaps/Sign (ms)": statistics.mean(sign_times),
        "Decaps/Verify (ms)": statistics.mean(verify_times),
        "PK Size (B)": 32,
        "CT/Sig Size (B)": 64
    })

    # --- 1.3 ML-KEM-1024 (FIPS 203) ---
    kem = LibOQS_MLKEM_1024()
    pk_sample, sk_sample = kem.keygen()
    ct_sample, _ = kem.encaps(pk_sample)

    keygen_times, encaps_times, decaps_times = [], [], []
    for _ in range(trials):
        t0 = time.perf_counter()
        pk, sk = kem.keygen()
        keygen_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        ct, ss1 = kem.encaps(pk)
        encaps_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        ss2 = kem.decaps(sk, ct)
        decaps_times.append((time.perf_counter() - t0) * 1000)

    results.append({
        "Algorithm": "ML-KEM-1024 (FIPS 203)",
        "Type": "Lattice KEM",
        "Security": "NIST Level 5 (256-bit PQ)",
        "Keygen (ms)": statistics.mean(keygen_times),
        "Encaps/Sign (ms)": statistics.mean(encaps_times),
        "Decaps/Verify (ms)": statistics.mean(decaps_times),
        "PK Size (B)": len(pk_sample),
        "CT/Sig Size (B)": len(ct_sample)
    })

    # --- 1.4 Classic McEliece-8192128f ---
    mceliece = LibOQS_McEliece_8192128f()
    mpk_sample, msk_sample = mceliece.keygen()
    mct_sample, _ = mceliece.encaps(mpk_sample)

    keygen_times, encaps_times, decaps_times = [], [], []
    for _ in range(min(trials, 5)):  # McEliece keygen is computation-heavy
        t0 = time.perf_counter()
        pk, sk = mceliece.keygen()
        keygen_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        ct, ss1 = mceliece.encaps(pk)
        encaps_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        ss2 = mceliece.decaps(sk, ct)
        decaps_times.append((time.perf_counter() - t0) * 1000)

    results.append({
        "Algorithm": "Classic McEliece-8192128f",
        "Type": "Code-Based KEM",
        "Security": "NIST Level 5 (Conservative PQ)",
        "Keygen (ms)": statistics.mean(keygen_times),
        "Encaps/Sign (ms)": statistics.mean(encaps_times),
        "Decaps/Verify (ms)": statistics.mean(decaps_times),
        "PK Size (B)": len(mpk_sample),
        "CT/Sig Size (B)": len(mct_sample)
    })

    # --- 1.5 Dual Post-Quantum KEM (ML-KEM-1024 + McEliece-8192128f) ---
    hybrid_kem = HybridKEM()
    hpk, hsk = hybrid_kem.keygen()
    hct, _ = hybrid_kem.encaps(hpk)

    keygen_times, encaps_times, decaps_times = [], [], []
    for _ in range(min(trials, 5)):
        t0 = time.perf_counter()
        hpk_i, hsk_i = hybrid_kem.keygen()
        keygen_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        hct_i, ss_s = hybrid_kem.encaps(hpk_i)
        encaps_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        ss_r = hybrid_kem.decaps(hsk_i, hct_i)
        decaps_times.append((time.perf_counter() - t0) * 1000)

    results.append({
        "Algorithm": "Dual Hybrid KEM (ML-KEM+McEliece)",
        "Type": "Lattice + Code KEM",
        "Security": "NIST Level 5+ (Dual PQ)",
        "Keygen (ms)": statistics.mean(keygen_times),
        "Encaps/Sign (ms)": statistics.mean(encaps_times),
        "Decaps/Verify (ms)": statistics.mean(decaps_times),
        "PK Size (B)": len(hpk),
        "CT/Sig Size (B)": len(hct)
    })

    # --- 1.6 FALCON-1024 (pre-standard; NOT FN-DSA) ---
    falcon = LibOQS_Falcon_1024()
    fpk, fsk = falcon.keygen()
    fsig = falcon.sign(fsk, test_msg)

    keygen_times, sign_times, verify_times = [], [], []
    for _ in range(trials):
        t0 = time.perf_counter()
        fpk_i, fsk_i = falcon.keygen()
        keygen_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        fsig_i = falcon.sign(fsk_i, test_msg)
        sign_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        falcon.verify(fpk_i, test_msg, fsig_i)
        verify_times.append((time.perf_counter() - t0) * 1000)

    results.append({
        "Algorithm": "FALCON-1024 (pre-standard, NOT FN-DSA)",
        "Type": "NTRU Lattice Signature",
        "Security": "NIST Level 5 (256-bit PQ)",
        "Keygen (ms)": statistics.mean(keygen_times),
        "Encaps/Sign (ms)": statistics.mean(sign_times),
        "Decaps/Verify (ms)": statistics.mean(verify_times),
        "PK Size (B)": len(fpk),
        "CT/Sig Size (B)": len(fsig)
    })

    # --- 1.7 ML-DSA-87 (FIPS 204 Dilithium-5) ---
    mldsa = LibOQS_MLDSA_87()
    dpk, dsk = mldsa.keygen()
    dsig = mldsa.sign(dsk, test_msg)

    keygen_times, sign_times, verify_times = [], [], []
    for _ in range(trials):
        t0 = time.perf_counter()
        dpk_i, dsk_i = mldsa.keygen()
        keygen_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        dsig_i = mldsa.sign(dsk_i, test_msg)
        sign_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        mldsa.verify(dpk_i, test_msg, dsig_i)
        verify_times.append((time.perf_counter() - t0) * 1000)

    results.append({
        "Algorithm": "ML-DSA-87 (FIPS 204)",
        "Type": "Module Lattice Signature",
        "Security": "NIST Level 5 (256-bit PQ)",
        "Keygen (ms)": statistics.mean(keygen_times),
        "Encaps/Sign (ms)": statistics.mean(sign_times),
        "Decaps/Verify (ms)": statistics.mean(verify_times),
        "PK Size (B)": len(dpk),
        "CT/Sig Size (B)": len(dsig)
    })

    # --- 1.8 SLH-DSA-256f (FIPS 205 SPHINCS+) ---
    slh = LibOQS_SLH_DSA_256f()
    spk, ssk = slh.keygen()
    ssig = slh.sign(ssk, test_msg)

    keygen_times, sign_times, verify_times = [], [], []
    for _ in range(min(trials, 5)):
        t0 = time.perf_counter()
        spk_i, ssk_i = slh.keygen()
        keygen_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        ssig_i = slh.sign(ssk_i, test_msg)
        sign_times.append((time.perf_counter() - t0) * 1000)

        t0 = time.perf_counter()
        slh.verify(spk_i, test_msg, ssig_i)
        verify_times.append((time.perf_counter() - t0) * 1000)

    results.append({
        "Algorithm": "SLH-DSA-256f (FIPS 205)",
        "Type": "Stateless Hash Signature",
        "Security": "NIST Level 5 (Conservative PQ)",
        "Keygen (ms)": statistics.mean(keygen_times),
        "Encaps/Sign (ms)": statistics.mean(sign_times),
        "Decaps/Verify (ms)": statistics.mean(verify_times),
        "PK Size (B)": len(spk),
        "CT/Sig Size (B)": len(ssig)
    })

    # Print Table
    header = f"{'Algorithm':<36} | {'Keygen':>10} | {'Enc/Sign':>10} | {'Dec/Ver':>10} | {'PK Size':>12} | {'CT/Sig Size':>12}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(f"{r['Algorithm']:<36} | {r['Keygen (ms)']:>8.3f} ms | {r['Encaps/Sign (ms)']:>8.3f} ms | {r['Decaps/Verify (ms)']:>8.3f} ms | {r['PK Size (B)']:>10,} B | {r['CT/Sig Size (B)']:>10,} B")

    return results

# ==============================================================================
# BENCHMARK 2: SYMMETRIC AEAD BULK CIPHER THROUGHPUT (AES-NI vs CHACHA20)
# ==============================================================================
def benchmark_symmetric_ciphers():
    print_section("STAGE 2: SYMMETRIC AEAD THROUGHPUT (AES-256-GCM vs CHACHA20-POLY1305)")
    print("Measuring encryption/decryption throughput across standard tactical payload sizes...\n")

    test_sizes = [
        ("64 Bytes (Ping/ACK)", 64, 10000),
        ("1 KB (Chaff / Normal Msg)", 1024, 5000),
        ("64 KB (File Chunk / Audio)", 64 * 1024, 1000),
        ("1 MB (Satellite Map / Intel)", 1024 * 1024, 100),
        ("10 MB (Heavy Classified Stream)", 10 * 1024 * 1024, 15)
    ]

    key256 = secrets.token_bytes(32)
    nonce12 = secrets.token_bytes(12)
    aad = b"AUTHENTICATED_SESSION_HEADER_V2"

    aes_gcm = AESGCM(key256)
    chacha = ChaCha20Poly1305(key256)

    print(f"{'Payload Size':<32} | {'Cipher':<18} | {'Latency':>10} | {'Throughput':>14} | {'Ops / Sec':>12}")
    print("-" * 96)

    symmetric_results = []

    for name, size, iterations in test_sizes:
        payload = secrets.token_bytes(size)

        # 2.1 AES-256-GCM Encrypt
        t0 = time.perf_counter()
        for _ in range(iterations):
            ct = aes_gcm.encrypt(nonce12, payload, aad)
        aes_enc_time = time.perf_counter() - t0
        aes_enc_mb_s = (size * iterations) / (aes_enc_time * 1024 * 1024)
        aes_enc_ops = iterations / aes_enc_time
        aes_lat = (aes_enc_time / iterations) * 1000

        # 2.2 ChaCha20-Poly1305 Encrypt
        t0 = time.perf_counter()
        for _ in range(iterations):
            ct = chacha.encrypt(nonce12, payload, aad)
        chacha_enc_time = time.perf_counter() - t0
        chacha_enc_mb_s = (size * iterations) / (chacha_enc_time * 1024 * 1024)
        chacha_enc_ops = iterations / chacha_enc_time
        chacha_lat = (chacha_enc_time / iterations) * 1000

        print(f"{name:<32} | {'AES-256-GCM':<18} | {aes_lat:>8.3f} ms | {aes_enc_mb_s:>10.2f} MB/s | {aes_enc_ops:>10.1f} op/s")
        print(f"{name:<32} | {'ChaCha20-Poly1305':<18} | {chacha_lat:>8.3f} ms | {chacha_enc_mb_s:>10.2f} MB/s | {chacha_enc_ops:>10.1f} op/s")
        
        ratio = aes_enc_mb_s / chacha_enc_mb_s
        faster = "AES-256-GCM (Hardware AES-NI)" if ratio >= 1 else "ChaCha20-Poly1305"
        diff = ratio if ratio >= 1 else (1/ratio)
        print(f"{DIM}  --> Performance Advantage: {faster} is {diff:.2f}x faster{RESET}")
        print("-" * 96)

        symmetric_results.append({
            "size_name": name,
            "size_bytes": size,
            "aes_mb_s": aes_enc_mb_s,
            "aes_lat_ms": aes_lat,
            "chacha_mb_s": chacha_enc_mb_s,
            "chacha_lat_ms": chacha_lat
        })

    return symmetric_results

# ==============================================================================
# BENCHMARK 3: POST-QUANTUM DOUBLE RATCHET STEPPING & PIPELINE LATENCY
# ==============================================================================
def benchmark_double_ratchet_pipeline(rounds: int = 30):
    print_section("STAGE 3: POST-QUANTUM DOUBLE RATCHET PERFORMANCE BENCHMARK")
    print(f"Measuring symmetric chain ratcheting, asymmetric DH ratcheting, and end-to-end messaging across {rounds} sequential messages...\n")

    shared_root = secrets.token_bytes(32)
    alice = DoubleRatchet(root_key=shared_root, is_initiator=True)
    bob = DoubleRatchet(root_key=shared_root, is_initiator=False)

    alice.set_remote_public_key(bob.get_public_key(), bob.get_kem_public_key(), bob.get_dss_public_key())
    bob.set_remote_public_key(alice.get_public_key(), alice.get_kem_public_key(), alice.get_dss_public_key())
    bob.process_kem_ciphertext(alice.get_kem_ciphertext())

    # Measure Symmetric Chain Ratchet Step (HMAC-SHA512)
    chain_key = secrets.token_bytes(32)
    t0 = time.perf_counter()
    for _ in range(1000):
        chain_key, msg_key = alice._chain_ratchet_step(chain_key)
    chain_step_time = (time.perf_counter() - t0) / 1000 * 1000  # ms per step
    chain_steps_per_sec = 1000 / (chain_step_time / 1000)

    print(f"  [RATCHET] Pure Symmetric Chain Step (HMAC-SHA512): {chain_step_time:.4f} ms ({chain_steps_per_sec:,.0f} steps/sec)")

    # Measure End-to-End Chat Messages with Full Ratchet Advancement
    test_message = b"TOP-SECRET STRATEGIC COMMAND ORDER: EXECUTE TACTICAL DEPLOYMENT ALPHA-7"
    encrypt_times = []
    decrypt_times = []
    ciphertext_sizes = []

    for i in range(rounds):
        sender = alice if i % 2 == 0 else bob
        receiver = bob if i % 2 == 0 else alice

        t0 = time.perf_counter()
        ct = sender.encrypt(test_message)
        encrypt_times.append((time.perf_counter() - t0) * 1000)
        ciphertext_sizes.append(len(ct))

        t0 = time.perf_counter()
        pt = receiver.decrypt(ct)
        decrypt_times.append((time.perf_counter() - t0) * 1000)

        assert pt == test_message, f"Decryption error at round {i}"  # nosec: B101

    avg_enc = statistics.mean(encrypt_times)
    avg_dec = statistics.mean(decrypt_times)
    avg_size = statistics.mean(ciphertext_sizes)

    print(f"  [RATCHET] Full Encrypt + Ratchet Advance + FALCON Sign:  {avg_enc:.3f} ms ({1000/avg_enc:,.1f} msg/sec)")
    print(f"  [RATCHET] Full Decrypt + Ratchet Advance + FALCON Verify: {avg_dec:.3f} ms ({1000/avg_dec:,.1f} msg/sec)")
    print(f"  [RATCHET] Average Wire Ciphertext Size (Header + Sig + AEAD Payload): {avg_size:,.0f} bytes")

    return {
        "chain_step_ms": chain_step_time,
        "chain_steps_sec": chain_steps_per_sec,
        "avg_encrypt_ms": avg_enc,
        "avg_decrypt_ms": avg_dec,
        "avg_ciphertext_bytes": avg_size
    }

# ==============================================================================
# BENCHMARK 4: HANDSHAKE BANDWIDTH WIRE OVERHEAD ANALYSIS
# ==============================================================================
def benchmark_handshake_wire_footprint():
    print_section("STAGE 4: PROTOCOL HANDSHAKE WIRE FOOTPRINT & OVERHEAD")
    print("Quantifying public key, ciphertext, and signature transmission volume on the wire...\n")

    # Classical X25519 + Ed25519 Handshake
    classical_pk = 32
    classical_sig = 64
    classical_total = (classical_pk * 2) + classical_sig

    # NIST Level 5 ML-KEM-1024 + FALCON-1024 Handshake
    mlkem_pk = 1568
    mlkem_ct = 1568
    falcon_pk = 1793
    falcon_sig = 1280
    nist_l5_total = mlkem_pk + mlkem_ct + falcon_pk + falcon_sig

    # State-Level Dual Hybrid KEM (ML-KEM-1024 + Classic McEliece) + Dual Signatures (ML-DSA-87 + SLH-DSA-256f)
    kem = HybridKEM()
    hpk, _ = kem.keygen()
    hct, _ = kem.encaps(hpk)
    sig_fast = LibOQS_MLDSA_87()
    spk_fast, ssk_fast = sig_fast.keygen()
    ssig_fast = sig_fast.sign(ssk_fast, b"HANDSHAKE_CERTIFICATE_BINDING")

    state_level_total = len(hpk) + len(hct) + len(spk_fast) + len(ssig_fast)

    print(f"{'Security Architecture':<42} | {'Total Wire Overhead':>20} | {'Quantum Immunity':<20}")
    print("-" * 88)
    print(f"{'Classical Baseline (X25519 + Ed25519)':<42} | {classical_total:>18,} B | {'VULNERABLE (Shor)':<20}")
    print(f"{'NIST Level 5 PQC (ML-KEM-1024 + FALCON-1024)':<42} | {nist_l5_total:>18,} B | {'IMMUNE (Level 5)':<20}")
    print(f"{'DoD Dual Hybrid (ML-KEM + McEliece + ML-DSA)':<42} | {state_level_total:>18,} B | {'MAXIMUM (Dual PQ)':<20}")

    print("\nBandwidth Breakdown for High-Assurance Hybrid Handshake:")
    print(f"  * ML-KEM-1024 + McEliece Public Key:   {len(hpk):,} bytes")
    print(f"  * ML-KEM-1024 + McEliece Ciphertext:   {len(hct):,} bytes")
    print(f"  * ML-DSA-87 Public Key:                 {len(spk_fast):,} bytes")
    print(f"  * ML-DSA-87 Authentication Signature:   {len(ssig_fast):,} bytes")
    print(f"  * Total Initial Handshake Data Volume:  {state_level_total:,} bytes (~{state_level_total/1024:.2f} KB)")
    print(f"  --> Transmitted securely over authenticated TLS channel in initial session handshake.")

    return {
        "classical_bytes": classical_total,
        "nist_l5_bytes": nist_l5_total,
        "dual_hybrid_bytes": state_level_total
    }

if __name__ == "__main__":
    print(f"\n{BOLD}{GREEN}Starting Master Military Cryptographic Benchmark Suite...{RESET}")
    start_all = time.time()
    b1 = benchmark_asymmetric_primitives(trials=15)
    b2 = benchmark_symmetric_ciphers()
    b3 = benchmark_double_ratchet_pipeline(rounds=20)
    b4 = benchmark_handshake_wire_footprint()
    total_elapsed = time.time() - start_all
    print(f"\n{BOLD}{GREEN}ALL BENCHMARK STAGES COMPLETED IN {total_elapsed:.2f}s!{RESET}\n")
