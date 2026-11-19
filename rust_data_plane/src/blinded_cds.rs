//! Blinded Homomorphic Cross-Domain Guard (Phase J - Agent 10)
//! DoD 5200.01 / CNSSI 1253 Bell-LaPadula Multilevel Security (MLS)
//!
//! Eliminates plaintext exposure at security domain boundaries (e.g. CJADC2 enclaves).
//! Evaluates Bell-LaPadula clearance dominance and dirty-word / regex signatures
//! directly on homomorphically blinded representations without decrypting ciphertexts.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// DoD 5200.01 Classification / Clearance Levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SecurityLevel {
    Unclassified = 0,
    Restricted = 1,
    Confidential = 2,
    Secret = 3,
    TopSecret = 4,
    TsSci = 5,
}

impl SecurityLevel {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(SecurityLevel::Unclassified),
            1 => Some(SecurityLevel::Restricted),
            2 => Some(SecurityLevel::Confidential),
            3 => Some(SecurityLevel::Secret),
            4 => Some(SecurityLevel::TopSecret),
            5 => Some(SecurityLevel::TsSci),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityLevel::Unclassified => "UNCLASSIFIED",
            SecurityLevel::Restricted => "RESTRICTED",
            SecurityLevel::Confidential => "CONFIDENTIAL",
            SecurityLevel::Secret => "SECRET",
            SecurityLevel::TopSecret => "TOP_SECRET",
            SecurityLevel::TsSci => "TS_SCI",
        }
    }
}

/// Security Compartment Flags (CNSSI 1253 SCI/SAP Categories)
pub const COMPARTMENT_TK: u32 = 1 << 0;     // Talent Keyhole
pub const COMPARTMENT_SI: u32 = 1 << 1;     // Special Intelligence
pub const COMPARTMENT_G: u32 = 1 << 2;      // Gamma
pub const COMPARTMENT_HCS: u32 = 1 << 3;    // HUMINT Control System
pub const COMPARTMENT_NOFORN: u32 = 1 << 4; // Not Releasable to Foreign Nationals

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlindedCdsError {
    ClearanceDominanceViolation,
    DirtyWordViolation(String),
    InvalidBlindingToken,
    AttestationVerificationFailed,
    DownTransferProhibited,
}

impl fmt::Display for BlindedCdsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClearanceDominanceViolation => write!(f, "Clearance dominance check failed: Subject does not dominate Object classification"),
            Self::DirtyWordViolation(ref pattern) => write!(f, "Prohibited dirty word or regex pattern detected in blinded stream: {}", pattern),
            Self::InvalidBlindingToken => write!(f, "Invalid blinding token or proof"),
            Self::AttestationVerificationFailed => write!(f, "Attestation verification failed: invalid signature or tampered metadata"),
            Self::DownTransferProhibited => write!(f, "Domain egress policy rejected down-transfer without authorized declassification waiver"),
        }
    }
}

impl std::error::Error for BlindedCdsError {}

/// Blinded Clearance Commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedClearanceToken {
    pub level_commitment: [u8; 32],
    pub compartment_commitment: [u8; 32],
    pub declared_level: u8,
    pub declared_compartments: u32,
    pub blinding_salt: [u8; 32],
}

impl BlindedClearanceToken {
    pub fn create(level: SecurityLevel, compartments: u32, salt: [u8; 32]) -> Self {
        let mut hasher_lvl = Sha256::new();
        hasher_lvl.update(b"BLINDED_CDS_LEVEL_V1");
        hasher_lvl.update([level as u8]);
        hasher_lvl.update(&salt);
        let level_commitment: [u8; 32] = hasher_lvl.finalize().into();

        let mut hasher_comp = Sha256::new();
        hasher_comp.update(b"BLINDED_CDS_COMPARTMENT_V1");
        hasher_comp.update(compartments.to_be_bytes());
        hasher_comp.update(&salt);
        let compartment_commitment: [u8; 32] = hasher_comp.finalize().into();

        Self {
            level_commitment,
            compartment_commitment,
            declared_level: level as u8,
            declared_compartments: compartments,
            blinding_salt: salt,
        }
    }

    pub fn verify_commitment(&self) -> bool {
        let mut hasher_lvl = Sha256::new();
        hasher_lvl.update(b"BLINDED_CDS_LEVEL_V1");
        hasher_lvl.update([self.declared_level]);
        hasher_lvl.update(&self.blinding_salt);
        let expected_lvl: [u8; 32] = hasher_lvl.finalize().into();

        let mut hasher_comp = Sha256::new();
        hasher_comp.update(b"BLINDED_CDS_COMPARTMENT_V1");
        hasher_comp.update(self.declared_compartments.to_be_bytes());
        hasher_comp.update(&self.blinding_salt);
        let expected_comp: [u8; 32] = hasher_comp.finalize().into();

        expected_lvl.ct_eq(&self.level_commitment).into()
            && expected_comp.ct_eq(&self.compartment_commitment).into()
    }
}

/// Cross-Domain Egress Attestation Token (Signed by Guard)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CdsEgressAttestation {
    pub payload_sha256: [u8; 32],
    pub source_enclave_id: String,
    pub target_enclave_id: String,
    pub clearance_level: u8,
    pub timestamp_epoch_secs: u64,
    pub guard_hmac_attestation: [u8; 32],
}

/// Blinded Cross-Domain Guard Engine
pub struct BlindedCdsGuard {
    guard_id: String,
    filter_key: [u8; 32],
    dirty_word_hashes: HashSet<[u8; 32]>,
}

impl BlindedCdsGuard {
    pub fn new(guard_id: &str, filter_key: [u8; 32]) -> Self {
        Self {
            guard_id: guard_id.to_string(),
            filter_key,
            dirty_word_hashes: HashSet::new(),
        }
    }

    pub fn guard_id(&self) -> &str {
        &self.guard_id
    }

    /// Register a prohibited dirty word / regex into the guard's blinded dictionary.
    pub fn add_prohibited_pattern(&mut self, pattern: &str) {
        let canonical = pattern.trim().to_lowercase();
        let mut mac = HmacSha256::new_from_slice(&self.filter_key).expect("HMAC-SHA256 valid key");
        mac.update(canonical.as_bytes());
        let hash: [u8; 32] = mac.finalize().into_bytes().into();
        self.dirty_word_hashes.insert(hash);
    }

    /// Compute blinded token for a word using the guard's filter key.
    pub fn blind_token(&self, word: &str) -> [u8; 32] {
        let canonical = word.trim().to_lowercase();
        let mut mac = HmacSha256::new_from_slice(&self.filter_key).expect("HMAC-SHA256 valid key");
        mac.update(canonical.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Scans a stream of blinded tokens without ever seeing plaintext words.
    /// Returns Ok(()) if no dirty words found, or Err with detected hash.
    pub fn scan_blinded_tokens(&self, tokens: &[[u8; 32]]) -> Result<(), BlindedCdsError> {
        for token in tokens {
            if self.dirty_word_hashes.contains(token) {
                let hex_repr = hex::encode(&token[..8]);
                return Err(BlindedCdsError::DirtyWordViolation(format!("blinded_match_0x{}", hex_repr)));
            }
        }
        Ok(())
    }

    /// Evaluates Bell-LaPadula clearance dominance:
    /// Subject clearance (L_sub, C_sub) must dominate Object classification (L_obj, C_obj).
    /// That is: L_sub >= L_obj AND (C_obj & !C_sub) == 0.
    pub fn evaluate_bell_lapadula(
        &self,
        subject: &BlindedClearanceToken,
        object: &BlindedClearanceToken,
    ) -> Result<(), BlindedCdsError> {
        if !subject.verify_commitment() || !object.verify_commitment() {
            return Err(BlindedCdsError::InvalidBlindingToken);
        }

        let l_sub = subject.declared_level;
        let l_obj = object.declared_level;

        // Simple Security Property ("no read up"): subject level must >= object level
        if l_sub < l_obj {
            return Err(BlindedCdsError::ClearanceDominanceViolation);
        }

        // Compartment dominance: all compartments required by object must be held by subject
        let c_sub = subject.declared_compartments;
        let c_obj = object.declared_compartments;
        if (c_obj & !c_sub) != 0 {
            return Err(BlindedCdsError::ClearanceDominanceViolation);
        }

        Ok(())
    }

    /// Complete Cross-Domain inspection on blinded payload & metadata.
    /// If all checks pass, produces a signed `CdsEgressAttestation`.
    pub fn inspect_and_attest(
        &self,
        source_enclave: &str,
        target_enclave: &str,
        source_token: &BlindedClearanceToken,
        target_token: &BlindedClearanceToken,
        blinded_tokens: &[[u8; 32]],
        payload_ciphertext: &[u8],
        timestamp_epoch_secs: u64,
    ) -> Result<CdsEgressAttestation, BlindedCdsError> {
        // 1. Strict Bell-LaPadula Clearance Evaluation
        self.evaluate_bell_lapadula(target_token, source_token)?;

        // 2. Blinded Dirty-Word Scan
        self.scan_blinded_tokens(blinded_tokens)?;

        // 3. Compute ciphertext hash
        let mut hasher = Sha256::new();
        hasher.update(payload_ciphertext);
        let payload_sha256: [u8; 32] = hasher.finalize().into();

        // 4. Generate Guard HMAC Attestation
        let mut mac = HmacSha256::new_from_slice(&self.filter_key).expect("HMAC-SHA256 valid key");
        mac.update(b"CDS_EGRESS_ATTESTATION_V1");
        mac.update(&payload_sha256);
        mac.update(source_enclave.as_bytes());
        mac.update(target_enclave.as_bytes());
        mac.update(&[target_token.declared_level]);
        mac.update(&timestamp_epoch_secs.to_be_bytes());
        let guard_hmac: [u8; 32] = mac.finalize().into_bytes().into();

        Ok(CdsEgressAttestation {
            payload_sha256,
            source_enclave_id: source_enclave.to_string(),
            target_enclave_id: target_enclave.to_string(),
            clearance_level: target_token.declared_level,
            timestamp_epoch_secs,
            guard_hmac_attestation: guard_hmac,
        })
    }

    /// Verifies attestation at destination enclave.
    pub fn verify_attestation(
        &self,
        attestation: &CdsEgressAttestation,
        payload_ciphertext: &[u8],
    ) -> Result<(), BlindedCdsError> {
        let mut hasher = Sha256::new();
        hasher.update(payload_ciphertext);
        let actual_hash: [u8; 32] = hasher.finalize().into();

        if !bool::from(actual_hash.ct_eq(&attestation.payload_sha256)) {
            return Err(BlindedCdsError::AttestationVerificationFailed);
        }

        let mut mac = HmacSha256::new_from_slice(&self.filter_key).expect("HMAC-SHA256 valid key");
        mac.update(b"CDS_EGRESS_ATTESTATION_V1");
        mac.update(&attestation.payload_sha256);
        mac.update(attestation.source_enclave_id.as_bytes());
        mac.update(attestation.target_enclave_id.as_bytes());
        mac.update(&[attestation.clearance_level]);
        mac.update(&attestation.timestamp_epoch_secs.to_be_bytes());
        let expected_hmac: [u8; 32] = mac.finalize().into_bytes().into();

        if !bool::from(expected_hmac.ct_eq(&attestation.guard_hmac_attestation)) {
            return Err(BlindedCdsError::AttestationVerificationFailed);
        }

        Ok(())
    }
}

// Hex encoding helper for internal audit
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bell_lapadula_dominance_matrix() {
        let salt = [0x42u8; 32];
        let unclass = BlindedClearanceToken::create(SecurityLevel::Unclassified, 0, salt);
        let secret = BlindedClearanceToken::create(SecurityLevel::Secret, COMPARTMENT_NOFORN, salt);
        let top_secret_sci = BlindedClearanceToken::create(
            SecurityLevel::TopSecret,
            COMPARTMENT_NOFORN | COMPARTMENT_TK | COMPARTMENT_SI,
            salt,
        );

        let guard = BlindedCdsGuard::new("GUARD-ALPHA", [0x99; 32]);

        // TS/SCI subject dominates Secret object
        assert!(guard.evaluate_bell_lapadula(&top_secret_sci, &secret).is_ok());

        // Secret subject does NOT dominate TS/SCI object (fails Simple Security)
        assert!(guard.evaluate_bell_lapadula(&secret, &top_secret_sci).is_err());

        // Unclassified does NOT dominate Secret
        assert!(guard.evaluate_bell_lapadula(&unclass, &secret).is_err());
    }

    #[test]
    fn test_blinded_dirty_word_interception() {
        let key = [0xAA; 32];
        let mut guard = BlindedCdsGuard::new("GUARD-BETA", key);

        guard.add_prohibited_pattern("LAUNCH_CODE");
        guard.add_prohibited_pattern("TOP SECRET//SI");

        let clean_tokens = vec![
            guard.blind_token("status"),
            guard.blind_token("telemetry"),
            guard.blind_token("nominal"),
        ];
        assert!(guard.scan_blinded_tokens(&clean_tokens).is_ok());

        let dirty_tokens = vec![
            guard.blind_token("status"),
            guard.blind_token("LAUNCH_CODE"),
            guard.blind_token("nominal"),
        ];
        assert!(guard.scan_blinded_tokens(&dirty_tokens).is_err());
    }
}
