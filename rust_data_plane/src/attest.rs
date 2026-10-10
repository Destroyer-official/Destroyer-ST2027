//! Enrollment-bound attestation verifier (Rust secure core).
//!
//! RATS RFC 9334 roles: the ATTESTER collects posture and signs; the
//! VERIFIER (this module) checks envelope shape, freshness (300 s),
//! nonce equality (constant-time), the device signature against an
//! INDEPENDENTLY ENROLLED trust anchor, then policy. A valid signature
//! under a self-supplied key alone NEVER authorizes — that only proves
//! "holder of this private key signed this envelope", not "this came
//! from the enrolled device".
//!
//! Reference: `ts_attest.py::appraise_evidence` (Python backup keeps the
//! same rule with `trusted_keys`; lab TOFU path exists ONLY in Python).
//! This crate has no TOFU path: unknown `kid` is `UnknownIdentity`,
//! mismatched key is `KeyMismatch`, always fail-closed.
//!
//! Device identity keys here are ML-DSA-87 enrollment pins (post-quantum).
//! The legacy TPM ECDSA-P256 device key (`cng_platform.py`, AIK tradition)
//! remains a Python-side attestation-identity mechanism only and never
//! covers data or session keys.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::Mldsa87VerifyingKey;
use crate::ct::ct_eq;
use crate::policy::{CoreError, FRESHNESS_S, NONCE_LEN};

/// Enrolled device identity: ML-DSA-87 public bytes (2592).
#[derive(Debug, Clone)]
pub struct EnrolledDevice {
    /// Canonical ML-DSA-87 public key bytes.
    pub pub_bytes: Vec<u8>,
}

/// Trust-anchor store: `kid -> enrolled device`. Populated out-of-band at
/// enrollment ceremony; never from the evidence envelope itself.
#[derive(Debug, Default)]
pub struct TrustAnchorStore {
    devices: HashMap<String, EnrolledDevice>,
}

impl TrustAnchorStore {
    /// Empty store (refuses everything until enrolled).
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    /// Enroll (or re-enroll) a device pin. `kid` is normalized to
    /// alphanumerics/`-`/`_`, max 64 chars (mirrors `trust_anchor.py`).
    pub fn enroll(&mut self, kid: &str, pub_bytes: Vec<u8>) -> Result<(), CoreError> {
        let norm = normalize_kid(kid)?;
        // Validate the pin parses as ML-DSA-87 (fail-closed on garbage).
        let vk = Mldsa87VerifyingKey::from_bytes(&pub_bytes)?;
        let _ = vk;
        self.devices.insert(norm, EnrolledDevice { pub_bytes });
        Ok(())
    }

    /// Look up an enrolled device (constant-time key compare below).
    pub fn get(&self, kid: &str) -> Option<&EnrolledDevice> {
        self.devices.get(kid)
    }
}

/// Evidence envelope submitted by the attester (parsed, untrusted).
pub struct Evidence<'a> {
    /// Key identifier (claimed; must be enrolled).
    pub kid: &'a str,
    /// Supplied public key bytes (attacker-controlled; must match enrollment).
    pub pub_bytes: &'a [u8],
    /// Signature over `message` (domain-separated by caller).
    pub sig: &'a [u8],
    /// Signed message (canonical posture binding; caller-constructed).
    pub message: &'a [u8],
    /// Challenge nonce (must equal expected, constant-time).
    pub nonce: &'a [u8],
    /// Expected challenge nonce.
    pub expected_nonce: &'a [u8],
    /// Evidence timestamp, seconds since UNIX epoch.
    pub ts: f64,
    /// Verification time, seconds since UNIX epoch (`None` = now).
    pub now: Option<f64>,
}

/// Posture claim evaluated by policy (booleans from the attester).
pub struct Posture {
    /// UEFI Secure Boot enabled and verified.
    pub secure_boot: bool,
    /// VBS enforced (status == 2 on Windows reference).
    pub vbs_enforced: bool,
    /// HVCI running.
    pub hvci_running: bool,
    /// Measured-boot log present and verified.
    pub measured_boot: bool,
    /// Deterministic native core present (version string non-empty).
    pub native_core: bool,
}

/// Policy verdict reasons (coarse, no oracle detail beyond posture bits
/// the attester itself supplied).
pub fn evaluate_policy(p: &Posture) -> Result<(), CoreError> {
    if !(p.secure_boot && p.vbs_enforced && p.hvci_running && p.measured_boot && p.native_core) {
        return Err(CoreError::Malformed);
    }
    Ok(())
}

/// Appraise evidence: enrollment bind → freshness → nonce → signature.
/// Order matters: identity and freshness are checked BEFORE signature
/// verification so unauthenticated inputs cannot become oracles.
pub fn appraise(
    store: &TrustAnchorStore,
    ev: &Evidence<'_>,
    verifier: &Mldsa87VerifyingKey,
    _domain: &[u8],
) -> Result<(), CoreError> {
    let norm = normalize_kid(ev.kid)?;
    // 1. Enrollment binding: kid must be enrolled; supplied pub must match
    //    the enrolled pin in constant time. Self-supplied keys prove nothing.
    let enrolled = store.get(&norm).ok_or(CoreError::UnknownIdentity)?;
    if !ct_eq(&enrolled.pub_bytes, ev.pub_bytes) {
        return Err(CoreError::KeyMismatch);
    }
    // The supplied pub must also parse (fail-closed on garbage pins).
    let supplied = Mldsa87VerifyingKey::from_bytes(ev.pub_bytes)?;
    // Belt-and-braces: supplied pin must equal the verifier pin used here.
    if !supplied.ct_pin_eq(&verifier.to_bytes()) {
        return Err(CoreError::KeyMismatch);
    }
    // 2. Freshness (absolute skew ≤ 300 s).
    let now = ev.now.unwrap_or_else(now_secs);
    if (now - ev.ts).abs() > FRESHNESS_S {
        return Err(CoreError::Stale);
    }
    // 3. Nonce equality (constant-time; lengths are public).
    if ev.nonce.len() != NONCE_LEN || ev.expected_nonce.len() != NONCE_LEN {
        return Err(CoreError::NonceMismatch);
    }
    if !ct_eq(ev.nonce, ev.expected_nonce) {
        return Err(CoreError::NonceMismatch);
    }
    // 4. Signature over the caller-constructed message.
    verifier.verify(_domain, ev.message, ev.sig)?;
    Ok(())
}

fn normalize_kid(kid: &str) -> Result<String, CoreError> {
    if kid.is_empty() || kid.len() > 64 {
        return Err(CoreError::Malformed);
    }
    let norm: String = kid
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if norm.is_empty() || norm.len() > 64 {
        return Err(CoreError::Malformed);
    }
    Ok(norm)
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Mldsa87SigningKey;

    fn enrolled_pair(kid: &str) -> (TrustAnchorStore, Mldsa87VerifyingKey, Mldsa87SigningKey) {
        let (sk, vk) = Mldsa87SigningKey::generate().unwrap();
        let mut store = TrustAnchorStore::new();
        store.enroll(kid, vk.to_bytes()).unwrap();
        (store, vk, sk)
    }

    #[test]
    fn honest_enrolled_device_passes() {
        let (store, vk, sk) = enrolled_pair("DEV-01");
        let msg = b"posture-binding";
        let domain = b"ST2027-ATTEST-v1";
        let sig = sk.sign(domain, msg);
        let nonce = [0x42u8; 32];
        let ev = Evidence {
            kid: "DEV-01",
            pub_bytes: &vk.to_bytes(),
            sig: &sig,
            message: msg,
            nonce: &nonce,
            expected_nonce: &nonce,
            ts: now_secs(),
            now: None,
        };
        appraise(&store, &ev, &vk, domain).unwrap();
    }

    #[test]
    fn substitution_and_tofu_refused() {
        let (store, vk, sk) = enrolled_pair("DEV-01");
        let (_sk2, vk2) = Mldsa87SigningKey::generate().unwrap();
        let msg = b"healthy-posture-forged";
        let domain = b"ST2027-ATTEST-v1";
        // Attacker signs with THEIR key: crypto-valid, identity-invalid.
        let forged = _sk2.sign(domain, msg);
        let nonce = [0x42u8; 32];
        let ev = Evidence {
            kid: "DEV-01",
            pub_bytes: &vk2.to_bytes(),
            sig: &forged,
            message: msg,
            nonce: &nonce,
            expected_nonce: &nonce,
            ts: now_secs(),
            now: None,
        };
        assert_eq!(
            appraise(&store, &ev, &vk, domain).unwrap_err(),
            CoreError::KeyMismatch
        );
        // Unknown kid: no TOFU path exists here.
        let sig = sk.sign(domain, msg);
        let ev2 = Evidence {
            kid: "ATTACKER-DEV",
            pub_bytes: &vk.to_bytes(),
            sig: &sig,
            message: msg,
            nonce: &nonce,
            expected_nonce: &nonce,
            ts: now_secs(),
            now: None,
        };
        assert_eq!(
            appraise(&store, &ev2, &vk, domain).unwrap_err(),
            CoreError::UnknownIdentity
        );
        // Stale + nonce-mismatch fail closed.
        let ev3 = Evidence {
            kid: "DEV-01",
            pub_bytes: &vk.to_bytes(),
            sig: &sig,
            message: msg,
            nonce: &nonce,
            expected_nonce: &nonce,
            ts: now_secs() - 3600.0,
            now: None,
        };
        assert_eq!(
            appraise(&store, &ev3, &vk, domain).unwrap_err(),
            CoreError::Stale
        );
        let other = [0x99u8; 32];
        let ev4 = Evidence {
            kid: "DEV-01",
            pub_bytes: &vk.to_bytes(),
            sig: &sig,
            message: msg,
            nonce: &nonce,
            expected_nonce: &other,
            ts: now_secs(),
            now: None,
        };
        assert_eq!(
            appraise(&store, &ev4, &vk, domain).unwrap_err(),
            CoreError::NonceMismatch
        );
    }
}
