//! Standalone Pre-Flight Binary Integrity Verifier (Out-of-Process Trust Anchor)
//! ==============================================================================
//! Enforces SLSA Level 3+ supply chain integrity by independently verifying native
//! DLL cryptographic digests before any Python or runtime processes are spawned.
//! Eliminates in-process circular verification dependencies (Finding F-04 / Blocker B-03).

use sha2::{Digest, Sha384};
use sha3::Sha3_512;
use std::fs;
use std::path::PathBuf;
use std::process::exit;

const OQS_SHA384: &str = "bed075001dddcf7395eeb11baa7c100f19a8a386d23c48115f41a225c24f38adfc3d9b86b2b4c5a3ed29dc62df5cf4eb";
const OQS_SHA3_512: &str = "c6af8151a04b750112f49c8d5ae39df1a4625b99dd0c1ac70385867b9308dc4d187a1cbb3ee034ce3c1c3ec9a72cd3147fdfaad74b1940bea16264b3af5ac0ea";

const SODIUM_SHA384: &str = "3259f45cb6d774320e3e1d7445d30ab608e0d1df92d3f685b54403c833c53d5c2a64157f0a12b7a848c91130fa9202c7";
const SODIUM_SHA3_512: &str = "31b92c7e2986d4a8a39cbab49b48de627352223db60ab3bdde10a371d1713f5f97c5c7205140878bab87fe0a992cffc151bd216be645ed3a8e27e78318d93cd0";

fn find_binary(filename: &str) -> Option<PathBuf> {
    let candidates = [
        PathBuf::from(filename),
        PathBuf::from("..").join(filename),
        PathBuf::from(std::env::current_exe().ok()?.parent()?.parent()?.parent()?).join(filename),
    ];
    for c in &candidates {
        if c.is_file() {
            return Some(c.clone());
        }
    }
    None
}

fn verify_file(name: &str, expected_sha384: &str, expected_sha3_512: &str) -> bool {
    let path = match find_binary(name) {
        Some(p) => p,
        None => {
            eprintln!("[FAIL] Critical dependency missing: {}", name);
            return false;
        }
    };

    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[FAIL] Failed to read {}: {}", path.display(), e);
            return false;
        }
    };

    let mut h384 = Sha384::new();
    h384.update(&data);
    let actual_sha384 = hex::encode(h384.finalize());

    let mut h3_512 = Sha3_512::new();
    h3_512.update(&data);
    let actual_sha3_512 = hex::encode(h3_512.finalize());

    if actual_sha384 != expected_sha384 {
        eprintln!("[FAIL] SHA-384 digest mismatch for {}: expected {}, got {}", name, expected_sha384, actual_sha384);
        return false;
    }

    if actual_sha3_512 != expected_sha3_512 {
        eprintln!("[FAIL] SHA3-512 digest mismatch for {}: expected {}, got {}", name, expected_sha3_512, actual_sha3_512);
        return false;
    }

    println!("  [PASS] {}: SHA-384 & SHA3-512 cryptographic digests match embedded pins", name);
    true
}

mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

fn main() {
    println!("==============================================================================");
    println!("STANDALONE OUT-OF-PROCESS BINARY VERIFIER (BLOCKER B-03 ENFORCEMENT)");
    println!("==============================================================================");

    let oqs_ok = verify_file("oqs.dll", OQS_SHA384, OQS_SHA3_512);
    let sodium_ok = verify_file("libsodium.dll", SODIUM_SHA384, SODIUM_SHA3_512);

    if oqs_ok && sodium_ok {
        println!("==============================================================================");
        println!("[SUCCESS] ALL CRITICAL NATIVE DEPENDENCIES VERIFIED (100% CLEAN)");
        println!("==============================================================================");
        exit(0);
    } else {
        eprintln!("==============================================================================");
        eprintln!("[FATAL] OUT-OF-PROCESS BINARY VERIFICATION FAILED — EXECUTION HALTED");
        eprintln!("==============================================================================");
        exit(1);
    }
}
