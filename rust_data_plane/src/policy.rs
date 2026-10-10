//! Secure-core policy: single source of fail-closed truth.
//!
//! The Rust core is ALWAYS strict. There are no environment-variable
//! downgrades, no TOFU mode, no legacy ratchet version, no argv secrets,
//! and no unauthenticated KEX. Lab flexibility lives in the Python
//! reference/backup tree (`noise_pq.py`, `double_ratchet.py`,
//! `trust_anchor.py`, `ts_attest.py`); this crate is the production gate.
//!
//! Research grounding:
//! - CNSA 2.0: ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204),
//!   AES-256-GCM, SHA-384 (SHA-512 allowed for HKDF internals).
//! - RFC 10024 hybrids: session safe while AT LEAST ONE KEM half holds;
//!   classical-only refused (`ClassicalOnlyRefused`).
//! - Signal PQXDH analyses (Fiedler/Guenther PKC 2025; Bhargavan USENIX
//!   2024): KEM ciphertext must bind the encapsulation key; transcript
//!   hashes must cover every transmitted bundle.
//! - Signal SPQR / Triple Ratchet (Dodis et al. 2025/078, Oct 2025):
//!   PCS requires FRESH KEM encaps per ratchet step; reuse refused.
//! - RATS RFC 9334: verifier trust comes from a trust-anchor store
//!   independent of the evidence; self-supplied keys prove nothing.
//! - liboqs upstream supports ONLY 0.16.0 (<0.16 unsupported;
//!   HQC CVE-2024-54137/2025-52473, XMSS CVE-2026-44518/46344). The Rust
//!   core uses pure-Rust `ml-kem`/`ml-dsa` crates and never loads `oqs.dll`.
//!
//! Every error is deliberately coarse (`CoreError`) — no oracle detail.

use core::fmt;

/// Fail-closed error. Display strings are fixed and coarse so callers
/// cannot be used as verification oracles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    /// Authentication material missing or invalid (PSK and/or ML-DSA).
    AuthRequired,
    /// Classical-only operation requested (never permitted here).
    ClassicalOnlyRefused,
    /// Legacy / reused-KEM ratchet requested (fresh-KEM v2 only).
    LegacyRatchetRefused,
    /// Malformed public key, ciphertext, signature, or envelope.
    Malformed,
    /// Signature verification failed (no detail: invalid vs. wrong key).
    BadSignature,
    /// Unknown device identity (kid not enrolled).
    UnknownIdentity,
    /// Enrolled key mismatch (not the enrolled device).
    KeyMismatch,
    /// Stale evidence (outside freshness window).
    Stale,
    /// Nonce mismatch (challenge not bound).
    NonceMismatch,
    /// OS randomness unavailable.
    OsRandom,
    /// Key file permission / ACL hardening failed.
    FilePermissions,
    /// Payload exceeds largest quantum.
    Oversize,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::AuthRequired => write!(f, "authentication required (PSK and/or ML-DSA)"),
            CoreError::ClassicalOnlyRefused => write!(f, "classical-only refused"),
            CoreError::LegacyRatchetRefused => write!(f, "legacy KEM-reuse ratchet refused (fresh v2 only)"),
            CoreError::Malformed => write!(f, "malformed cryptographic input"),
            CoreError::BadSignature => write!(f, "signature verification failed"),
            CoreError::UnknownIdentity => write!(f, "unknown device identity"),
            CoreError::KeyMismatch => write!(f, "device key mismatch"),
            CoreError::Stale => write!(f, "stale evidence"),
            CoreError::NonceMismatch => write!(f, "nonce mismatch"),
            CoreError::OsRandom => write!(f, "OS randomness unavailable"),
            CoreError::FilePermissions => write!(f, "key file permission hardening failed"),
            CoreError::Oversize => write!(f, "payload exceeds largest quantum"),
        }
    }
}

impl std::error::Error for CoreError {}

/// ML-KEM-1024 sizes (FIPS 203 Table 3). Pinned, never negotiated.
pub const MLKEM1024_PK: usize = 1568;
/// ML-KEM-1024 ciphertext size.
pub const MLKEM1024_CT: usize = 1568;
/// ML-DSA-87 sizes (FIPS 204). Public 2592, signature 4627.
pub const MLDSA87_PK: usize = 2592;
/// ML-DSA-87 signature size.
pub const MLDSA87_SIG: usize = 4627;
/// X25519 public key size (interop leg only, never alone).
pub const X25519_PK: usize = 32;
/// Attestation freshness window, seconds (matches `ts_attest.py`).
pub const FRESHNESS_S: f64 = 300.0;
/// Attestation nonce length, bytes.
pub const NONCE_LEN: usize = 32;
/// SAS length, bytes (first 16 of SHA-384 transcript).
pub const SAS_LEN: usize = 16;
/// Maximum skipped message keys (Signal default).
pub const MAX_SKIPPED_KEYS: usize = 1000;
/// KEX transcript hash length (SHA-384).
pub const TRANSCRIPT_LEN: usize = 48;

/// Domain separators. Every KDF/signature context is domain-separated;
/// cross-protocol and cross-role reflection is refused by construction.
pub const DOMAIN_KEX_SESSION: &[u8] = b"ST2027-KEX-v2::session";
/// Responder signature domain (role-separated).
pub const DOMAIN_SIG_RESPONDER: &[u8] = b"ST2027-KEX-v2::sig-responder";
/// Initiator signature domain (role-separated).
pub const DOMAIN_SIG_INITIATOR: &[u8] = b"ST2027-KEX-v2::sig-initiator";
/// Ratchet chain domain.
pub const DOMAIN_RATCHET_CHAIN: &[u8] = b"ST2027-RATCHET-v2::chain";
/// Ratchet root domain.
pub const DOMAIN_RATCHET_ROOT: &[u8] = b"ST2027-RATCHET-v2::root";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_coarse() {
        // No key material, no offsets, no distinguishing detail.
        assert_eq!(format!("{}", CoreError::BadSignature), "signature verification failed");
        assert_eq!(format!("{}", CoreError::KeyMismatch), "device key mismatch");
        assert!(format!("{}", CoreError::AuthRequired).len() > 8);
    }

    #[test]
    fn pinned_sizes_match_fips() {
        assert_eq!(MLKEM1024_PK, 1568);
        assert_eq!(MLKEM1024_CT, 1568);
        assert_eq!(MLDSA87_PK, 2592);
        assert_eq!(MLDSA87_SIG, 4627);
        assert_eq!(TRANSCRIPT_LEN, 48);
    }

    #[test]
    fn domains_are_separated() {
        assert_ne!(DOMAIN_SIG_RESPONDER, DOMAIN_SIG_INITIATOR);
        assert_ne!(DOMAIN_KEX_SESSION, DOMAIN_RATCHET_ROOT);
    }
}
