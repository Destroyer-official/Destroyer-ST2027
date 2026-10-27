//! 3-of-5 threshold ML-DSA-87 PKI verification (Rust secure core).
//!
//! Byte-identical canonical encodings to the Python reference
//! (`trust_anchor.py`): five independent ML-DSA-87 custodian keys, a
//! certificate/revocation is valid only with ≥3 DISTINCT custodian
//! signatures over the canonical TBS. This is multi-signature quorum
//! (NOT Shamir secret sharing — see README correction).
//!
//! ```text
//! cert body   = b"CA-CERT-v1" || serial(16) || subject(norm ≤64) || pk(2592)
//!               || not_before u64BE || not_after u64BE
//! revoke body = b"CA-REVOKE-v1" || serial(16) || reason(norm ≤32)
//!               || ts_ms u64BE || seq u64BE
//! ```
//! Rules mirrored: exactly 5 distinct enrolled custodians, validity span
//! in (0, 48h], ±5 s future skew tolerated, duplicate signer labels
//! refused, pins 2592 bytes, quorum ≥3, coarse errors (no oracle detail).
//!
//! Research: RFC 9881 (ML-DSA in X.509 PKIX, pure variant); KSK-ceremony
//! dual-control shape (3-of-5 with witnessed scripts); industry retreat
//! from OCSP toward CRL-style hash-bound revocation (privacy + CVE
//! history) — revocation here is CRL-style with monotonic per-serial
//! sequence numbers; replays/stale broadcasts refused.

use std::collections::{HashMap, HashSet};

use crate::auth::Mldsa87VerifyingKey;
use crate::policy::{CoreError, MLDSA87_PK};

/// Certificate domain (identical to `trust_anchor._CERT_DOMAIN`).
pub const CERT_DOMAIN: &[u8] = b"CA-CERT-v1";
/// Revocation domain (identical to `trust_anchor._REVOKE_DOMAIN`).
pub const REVOKE_DOMAIN: &[u8] = b"CA-REVOKE-v1";
/// Quorum: valid signatures required.
pub const QUORUM: usize = 3;
/// Total enrolled custodians required.
pub const TOTAL: usize = 5;
/// Maximum certificate lifetime, seconds (48 h).
pub const MAX_LIFETIME: u64 = 48 * 3600;
/// Future-skew tolerance, seconds.
pub const MAX_SKEW_FUTURE: f64 = 5.0;

/// Normalize an identifier: alphanumerics + `-`/`_`, max 64 chars.
/// Mirrors `trust_anchor._norm_ident`.
pub fn norm_ident(value: &str) -> Result<String, CoreError> {
    let norm: String = value
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if norm.is_empty() {
        return Err(CoreError::Malformed);
    }
    Ok(norm)
}

/// Normalize a revocation reason: alphanumerics + `-`/`_`, max 32 chars.
pub fn norm_reason(value: &str) -> Result<String, CoreError> {
    let norm: String = value
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();
    if norm.is_empty() {
        return Err(CoreError::Malformed);
    }
    Ok(norm)
}

/// Canonical certificate TBS bytes (identical to `trust_anchor.tbs_bytes`).
pub fn tbs_bytes(
    serial: &[u8],
    subject: &str,
    subject_pk: &[u8],
    not_before: u64,
    not_after: u64,
) -> Result<Vec<u8>, CoreError> {
    if serial.len() != 16 || subject_pk.len() != MLDSA87_PK {
        return Err(CoreError::Malformed);
    }
    let subj = norm_ident(subject)?;
    let mut b = Vec::with_capacity(CERT_DOMAIN.len() + 16 + 64 + MLDSA87_PK + 16);
    b.extend_from_slice(CERT_DOMAIN);
    b.extend_from_slice(serial);
    b.extend_from_slice(subj.as_bytes());
    b.extend_from_slice(subject_pk);
    b.extend_from_slice(&not_before.to_be_bytes());
    b.extend_from_slice(&not_after.to_be_bytes());
    Ok(b)
}

/// Canonical revocation bytes (identical to `trust_anchor.revoke_bytes`).
/// `ts` is seconds (float, as in Python); encoded as integer milliseconds.
pub fn revoke_bytes(serial: &[u8], reason: &str, ts: f64, seq: u64) -> Result<Vec<u8>, CoreError> {
    if serial.len() != 16 {
        return Err(CoreError::Malformed);
    }
    if !(ts.is_finite()) || ts < 0.0 {
        return Err(CoreError::Malformed);
    }
    let r = norm_reason(reason)?;
    let mut b = Vec::with_capacity(REVOKE_DOMAIN.len() + 16 + 32 + 16);
    b.extend_from_slice(REVOKE_DOMAIN);
    b.extend_from_slice(serial);
    b.extend_from_slice(r.as_bytes());
    b.extend_from_slice(&((ts * 1000.0) as u64).to_be_bytes());
    b.extend_from_slice(&seq.to_be_bytes());
    Ok(b)
}

/// Enrolled custodian: normalized label + ML-DSA-87 public pin.
#[derive(Debug, Clone)]
pub struct Custodian {
    /// Normalized label.
    pub label: String,
    /// 2592-byte ML-DSA-87 public key.
    pub mldsa_pk: Vec<u8>,
}

impl Custodian {
    /// Enroll a custodian (label normalized, pin validated as ML-DSA-87).
    pub fn new(label: &str, mldsa_pk: Vec<u8>) -> Result<Self, CoreError> {
        let label = norm_ident(label)?;
        Mldsa87VerifyingKey::from_bytes(&mldsa_pk)?;
        Ok(Self { label, mldsa_pk })
    }
}

/// One custodian signature over a canonical body.
pub struct CertSig<'a> {
    /// Custodian label (claimed; must be enrolled, distinct).
    pub custodian: &'a str,
    /// ML-DSA-87 signature bytes.
    pub sig: &'a [u8],
}

fn check_custodian_set(custodians: &[Custodian]) -> Result<HashMap<&str, &[u8]>, CoreError> {
    let mut by_label: HashMap<&str, &[u8]> = HashMap::new();
    for c in custodians {
        if by_label.insert(c.label.as_str(), &c.mldsa_pk).is_some() {
            return Err(CoreError::Malformed); // duplicate enrollment
        }
    }
    if by_label.len() != TOTAL {
        return Err(CoreError::Malformed);
    }
    Ok(by_label)
}

fn check_quorum(
    body: &[u8],
    sigs: &[CertSig<'_>],
    by_label: &HashMap<&str, &[u8]>,
) -> Result<(), CoreError> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut valid = 0usize;
    for entry in sigs {
        // Duplicate signer label refused (one rogue custodian, one vote).
        if !seen.insert(entry.custodian) {
            return Err(CoreError::Malformed);
        }
        let pub_bytes = by_label
            .get(entry.custodian)
            .ok_or(CoreError::UnknownIdentity)?;
        if pub_bytes.len() != MLDSA87_PK {
            return Err(CoreError::Malformed);
        }
        // The enrolled pin looked up by label is exactly what verifies —
        // no self-supplied key material enters this path (contrast the
        // pre-hardening `ts_attest` flaw this design answers).
        let vk = Mldsa87VerifyingKey::from_bytes(pub_bytes)?;
        vk.verify(&[], body, entry.sig)?;
        valid += 1;
    }
    if valid < QUORUM {
        return Err(CoreError::Malformed);
    }
    Ok(())
}

/// Verify a threshold certificate (mirrors `trust_anchor.verify_certificate`).
/// Returns the canonical body on success (callers bind issuance from it).
#[allow(clippy::too_many_arguments)]
pub fn verify_certificate(
    serial: &[u8],
    subject: &str,
    subject_pk: &[u8],
    not_before: u64,
    not_after: u64,
    sigs: &[CertSig<'_>],
    custodians: &[Custodian],
    now: f64,
) -> Result<Vec<u8>, CoreError> {
    if !now.is_finite() {
        return Err(CoreError::Malformed);
    }
    let body = tbs_bytes(serial, subject, subject_pk, not_before, not_after)?;
    let span = not_after
        .checked_sub(not_before)
        .ok_or(CoreError::Malformed)?;
    if span == 0 || span > MAX_LIFETIME {
        return Err(CoreError::Malformed);
    }
    if !((not_before as f64) - MAX_SKEW_FUTURE <= now && now <= not_after as f64) {
        return Err(CoreError::Stale);
    }
    let by_label = check_custodian_set(custodians)?;
    check_quorum(&body, sigs, &by_label)?;
    Ok(body)
}

/// Monotonic per-serial revocation cache (CRL-style). Replays and stale
/// broadcasts are refused by sequence comparison.
///
/// INTENTIONAL DIVERGENCE from `trust_anchor.verify_revocation` (fail-closed
/// direction, documented): the Python reference verifies quorum over
/// whatever custodian set it is given, while this crate requires the full
/// exactly-5 ceremony set for revocations too — a rogue 3-of-3 sub-ceremony
/// cannot revoke here. Interop holds for full-ceremony sets (proven by
/// `tests/test_rust_interop.py`).
#[derive(Debug, Default)]
pub struct RevocationCache {
    max_seq: HashMap<Vec<u8>, u64>,
}

impl RevocationCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self {
            max_seq: HashMap::new(),
        }
    }

    /// Verify a threshold revocation and apply it iff its sequence is
    /// strictly newer than any cached entry for the serial.
    pub fn apply(
        &mut self,
        serial: &[u8],
        reason: &str,
        ts: f64,
        seq: u64,
        sigs: &[CertSig<'_>],
        custodians: &[Custodian],
    ) -> Result<(), CoreError> {
        if serial.len() != 16 {
            return Err(CoreError::Malformed);
        }
        let body = revoke_bytes(serial, reason, ts, seq)?;
        let by_label = check_custodian_set(custodians)?;
        check_quorum(&body, sigs, &by_label)?;
        match self.max_seq.get(serial) {
            Some(&prev) if seq <= prev => Err(CoreError::Stale),
            _ => {
                self.max_seq.insert(serial.to_vec(), seq);
                Ok(())
            }
        }
    }

    /// Highest applied sequence for a serial (None = never revoked).
    pub fn seq_for(&self, serial: &[u8]) -> Option<u64> {
        self.max_seq.get(serial).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Mldsa87SigningKey;

    struct CA {
        labels: Vec<String>,
        signers: Vec<Mldsa87SigningKey>,
        custodians: Vec<Custodian>,
    }

    fn test_ca() -> CA {
        let mut labels = Vec::new();
        let mut signers = Vec::new();
        let mut custodians = Vec::new();
        for i in 0..TOTAL {
            let label = format!("custodian-{i}");
            let (sk, vk) = Mldsa87SigningKey::generate().unwrap();
            custodians.push(Custodian::new(&label, vk.to_bytes()).unwrap());
            labels.push(label);
            signers.push(sk);
        }
        CA {
            labels,
            signers,
            custodians,
        }
    }

    #[test]
    fn quorum_cert_verifies_and_minority_fails() {
        let ca = test_ca();
        let (_, subj_vk) = Mldsa87SigningKey::generate().unwrap();
        let serial = [0xABu8; 16];
        let body = tbs_bytes(&serial, "node-alpha", &subj_vk.to_bytes(), 1000, 2000).unwrap();
        // 3-of-5 signs (quorum exactly).
        let sigs: Vec<Vec<u8>> = ca.signers[..3].iter().map(|s| s.sign(&[], &body)).collect();
        let entries: Vec<CertSig> = sigs
            .iter()
            .enumerate()
            .map(|(i, s)| CertSig {
                custodian: &ca.labels[i],
                sig: s,
            })
            .collect();
        let back = verify_certificate(
            &serial,
            "node-alpha",
            &subj_vk.to_bytes(),
            1000,
            2000,
            &entries,
            &ca.custodians,
            1500.0,
        )
        .unwrap();
        assert_eq!(back, body);
        // Only 2 signatures: quorum refused.
        let entries2: Vec<CertSig> = sigs
            .iter()
            .take(2)
            .enumerate()
            .map(|(i, s)| CertSig {
                custodian: &ca.labels[i],
                sig: s,
            })
            .collect();
        assert!(verify_certificate(
            &serial,
            "node-alpha",
            &subj_vk.to_bytes(),
            1000,
            2000,
            &entries2,
            &ca.custodians,
            1500.0
        )
        .is_err());
        // Duplicate signer label refused even with 3 entries.
        let entries3 = vec![
            CertSig {
                custodian: &ca.labels[0],
                sig: &sigs[0],
            },
            CertSig {
                custodian: &ca.labels[0],
                sig: &sigs[0],
            },
            CertSig {
                custodian: &ca.labels[1],
                sig: &sigs[1],
            },
        ];
        assert!(verify_certificate(
            &serial,
            "node-alpha",
            &subj_vk.to_bytes(),
            1000,
            2000,
            &entries3,
            &ca.custodians,
            1500.0
        )
        .is_err());
        // Expired / oversize-span / wrong-set-size refused.
        assert!(verify_certificate(
            &serial,
            "node-alpha",
            &subj_vk.to_bytes(),
            1000,
            2000,
            &entries,
            &ca.custodians,
            99999.0
        )
        .is_err());
        assert!(verify_certificate(
            &serial,
            "node-alpha",
            &subj_vk.to_bytes(),
            1000,
            1000 + MAX_LIFETIME + 1,
            &entries,
            &ca.custodians,
            1500.0
        )
        .is_err());
        assert!(verify_certificate(
            &serial,
            "node-alpha",
            &subj_vk.to_bytes(),
            1000,
            2000,
            &entries,
            &ca.custodians[..4],
            1500.0
        )
        .is_err());
    }

    #[test]
    fn revocation_cache_is_monotonic() {
        let ca = test_ca();
        let serial = [0xCDu8; 16];
        let mut cache = RevocationCache::new();
        let apply_seq = |cache: &mut RevocationCache, ca: &CA, seq: u64| {
            let body = revoke_bytes(&serial, "compromise", 5000.0, seq).unwrap();
            let sigs: Vec<Vec<u8>> = ca.signers[..3].iter().map(|s| s.sign(&[], &body)).collect();
            let entries: Vec<CertSig> = sigs
                .iter()
                .enumerate()
                .map(|(i, s)| CertSig {
                    custodian: ca.labels[i].as_str(),
                    sig: s,
                })
                .collect();
            cache.apply(&serial, "compromise", 5000.0, seq, &entries, &ca.custodians)
        };
        apply_seq(&mut cache, &ca, 1).unwrap();
        assert_eq!(cache.seq_for(&serial), Some(1));
        // Replay of seq 1 and older refused.
        assert!(apply_seq(&mut cache, &ca, 1).is_err());
        // Newer seq applies.
        apply_seq(&mut cache, &ca, 2).unwrap();
        assert_eq!(cache.seq_for(&serial), Some(2));
    }

    #[test]
    fn tbs_layout_matches_reference_shape() {
        // Domain || serial(16) || subject || pk(2592) || nb(8) || na(8).
        let pk = vec![0x11u8; MLDSA87_PK];
        let b = tbs_bytes(&[0x01u8; 16], "ab", &pk, 7, 9).unwrap();
        assert_eq!(b.len(), 10 + 16 + 2 + MLDSA87_PK + 8 + 8);
        assert_eq!(&b[..10], b"CA-CERT-v1");
        assert_eq!(&b[10..26], &[0x01u8; 16]);
        assert_eq!(&b[26..28], b"ab");
        assert_eq!(&b[b.len() - 16..b.len() - 8], &7u64.to_be_bytes());
        assert_eq!(&b[b.len() - 8..], &9u64.to_be_bytes());
        // Identifier normalization mirrors the reference (strip + cap).
        assert_eq!(norm_ident("a/b?c"), Ok("abc".to_string()));
        assert!(norm_ident("///").is_err());
    }
}
