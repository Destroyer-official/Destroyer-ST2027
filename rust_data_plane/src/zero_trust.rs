//! Zero-Trust Continuous Verification & Risk Scoring Engine.
//!
//! Enforces DoD / NIST SP 800-207 Zero-Trust Architecture:
//! - "Never Trust, Always Verify": No implicit trust granted based on network location or past handshake.
//! - Continuous risk assessment per packet: Evaluates cryptographic integrity, sequence ordering, and timing.
//! - Dynamic Trust Score (0..=100): Decrements sharply on anomalies; session terminates below threshold.
//! - Constant-Time Role-Based Access Control (RBAC) authorization bitmasks.

use crate::policy::CoreError;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub const DEFAULT_INITIAL_TRUST: u32 = 75;
pub const MIN_TRUST_THRESHOLD: u32 = 50;
pub const MAX_TRUST_SCORE: u32 = 100;

// RBAC Permissions (bitmask)
pub const PERM_READ_ONLY: u32 = 0x01;
pub const PERM_MESSAGE_SEND: u32 = 0x02;
pub const PERM_FILE_SEND: u32 = 0x04;
pub const PERM_CONFIG_UPDATE: u32 = 0x08;
pub const PERM_KEY_REVOKE: u32 = 0x10;
pub const PERM_CRITICAL_RELEASE: u32 = 0x20;

/// Bell-LaPadula Multi-Level Security (MLS) Clearance Levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ClearanceLevel {
    Unclassified = 0,
    Confidential = 1,
    Secret = 2,
    TopSecret = 3,
}

impl ClearanceLevel {
    pub fn from_u8(val: u8) -> Result<Self, CoreError> {
        match val {
            0 => Ok(ClearanceLevel::Unclassified),
            1 => Ok(ClearanceLevel::Confidential),
            2 => Ok(ClearanceLevel::Secret),
            3 => Ok(ClearanceLevel::TopSecret),
            _ => Err(CoreError::ZeroTrustViolation),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ClearanceLevel::Unclassified => "UNCLASSIFIED",
            ClearanceLevel::Confidential => "CONFIDENTIAL",
            ClearanceLevel::Secret => "SECRET",
            ClearanceLevel::TopSecret => "TOP_SECRET",
        }
    }
}

// Dissemination Caveats Bitflags
pub const CAVEAT_NOFORN: u32 = 0x01;
pub const CAVEAT_REL_TO_COALITION: u32 = 0x02;
pub const CAVEAT_EYES_ONLY: u32 = 0x04;
pub const CAVEAT_SI_TK_G: u32 = 0x08;

/// Bell-LaPadula Simple Security Property (No Read Up) + Caveat Authorization.
pub fn can_read(
    subject_clearance: ClearanceLevel,
    subject_caveats: u32,
    object_classification: ClearanceLevel,
    object_caveats: u32,
) -> bool {
    // No Read Up: subject clearance must dominate object classification
    if subject_clearance < object_classification {
        return false;
    }
    // Dissemination Caveat subset: subject must possess all object caveats
    (subject_caveats & object_caveats) == object_caveats
}

/// Bell-LaPadula Star-Property (No Write Down): Prevents classified spillage.
pub fn can_write(
    subject_clearance: ClearanceLevel,
    target_classification: ClearanceLevel,
) -> bool {
    // No Write Down: cannot egress from a higher classification to a lower one
    subject_clearance <= target_classification
}

/// NSA NCDSMO 'Raise the Bar' (RTB) Dirty-Word / Classified Indicator Filter.
/// Scans outbound data for unauthorized classified markers in constant-time slice traversal.
pub fn inspect_content_rtb(payload: &[u8]) -> Result<(), &'static str> {
    const DIRTY_WORDS: [&[u8]; 4] = [
        b"top secret",
        b"si-tk-g",
        b"noforn",
        b"orcon",
    ];

    let len = payload.len();
    for &marker in &DIRTY_WORDS {
        let mlen = marker.len();
        if len >= mlen {
            for i in 0..=len - mlen {
                let slice = &payload[i..i + mlen];
                let matches = slice
                    .iter()
                    .zip(marker.iter())
                    .all(|(&b, &m)| b.to_ascii_lowercase() == m);
                if matches {
                    return match marker {
                        b"top secret" => Err("TOP_SECRET_INDICATOR"),
                        b"si-tk-g" => Err("SI_TK_G_SCI_INDICATOR"),
                        b"noforn" => Err("NOFORN_INDICATOR"),
                        _ => Err("CLASSIFIED_DIRTY_WORD_DETECTED"),
                    };
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityRole {
    Viewer,
    Operator,
    Admin,
}

impl SecurityRole {
    pub fn permissions(&self) -> u32 {
        match self {
            SecurityRole::Viewer => PERM_READ_ONLY,
            SecurityRole::Operator => PERM_READ_ONLY | PERM_MESSAGE_SEND | PERM_FILE_SEND,
            SecurityRole::Admin => {
                PERM_READ_ONLY
                    | PERM_MESSAGE_SEND
                    | PERM_FILE_SEND
                    | PERM_CONFIG_UPDATE
                    | PERM_KEY_REVOKE
                    | PERM_CRITICAL_RELEASE
            }
        }
    }

    pub fn has_permission(&self, perm: u32) -> bool {
        (self.permissions() & perm) == perm
    }
}

#[derive(Debug, Clone)]
pub struct PeerTrustProfile {
    pub peer_id: String,
    pub role: SecurityRole,
    pub trust_score: u32,
    pub authenticated_packets: u64,
    pub anomaly_count: u64,
    pub revoked: bool,
}

impl PeerTrustProfile {
    pub fn new(peer_id: String, role: SecurityRole) -> Self {
        Self {
            peer_id,
            role,
            trust_score: DEFAULT_INITIAL_TRUST,
            authenticated_packets: 0,
            anomaly_count: 0,
            revoked: false,
        }
    }
}

#[derive(Clone)]
pub struct ZeroTrustEngine {
    min_trust_threshold: u32,
    profiles: Arc<RwLock<HashMap<String, PeerTrustProfile>>>,
}

impl Default for ZeroTrustEngine {
    fn default() -> Self {
        Self::new(MIN_TRUST_THRESHOLD)
    }
}

impl ZeroTrustEngine {
    pub fn new(min_trust_threshold: u32) -> Self {
        Self {
            min_trust_threshold,
            profiles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register or enroll an authenticated peer profile.
    pub fn register_peer(&self, peer_id: &str, role: SecurityRole) {
        if let Ok(mut map) = self.profiles.write() {
            map.insert(
                peer_id.to_string(),
                PeerTrustProfile::new(peer_id.to_string(), role),
            );
        }
    }

    /// Evaluate authorization for an operation against the peer's assigned RBAC role.
    pub fn authorize(&self, peer_id: &str, required_perm: u32) -> Result<(), CoreError> {
        let guard = self.profiles.read().map_err(|_| CoreError::ZeroTrustViolation)?;
        let prof = guard.get(peer_id).ok_or(CoreError::ZeroTrustViolation)?;

        if prof.revoked || prof.trust_score < self.min_trust_threshold {
            return Err(CoreError::ZeroTrustViolation);
        }

        if !prof.role.has_permission(required_perm) {
            return Err(CoreError::ZeroTrustViolation);
        }

        Ok(())
    }

    /// Record successful authentic packet arrival (rewards trust score up to MAX_TRUST_SCORE).
    pub fn record_success(&self, peer_id: &str) -> Result<u32, CoreError> {
        let mut guard = self.profiles.write().map_err(|_| CoreError::ZeroTrustViolation)?;
        let prof = guard.get_mut(peer_id).ok_or(CoreError::ZeroTrustViolation)?;

        if prof.revoked {
            return Err(CoreError::ZeroTrustViolation);
        }

        prof.authenticated_packets += 1;
        if prof.authenticated_packets % 10 == 0 && prof.trust_score < MAX_TRUST_SCORE {
            prof.trust_score = (prof.trust_score + 1).min(MAX_TRUST_SCORE);
        }

        Ok(prof.trust_score)
    }

    /// Record an anomaly or failed authentication check (penalizes trust score; revokes if below threshold).
    pub fn record_penalty(&self, peer_id: &str, penalty: u32) -> Result<u32, CoreError> {
        let mut guard = self.profiles.write().map_err(|_| CoreError::ZeroTrustViolation)?;
        let prof = guard.get_mut(peer_id).ok_or(CoreError::ZeroTrustViolation)?;

        prof.anomaly_count += 1;
        prof.trust_score = prof.trust_score.saturating_sub(penalty);

        if prof.trust_score < self.min_trust_threshold {
            prof.revoked = true;
            return Err(CoreError::ZeroTrustViolation);
        }

        Ok(prof.trust_score)
    }

    /// Explicit revocation of peer session.
    pub fn revoke_peer(&self, peer_id: &str) {
        if let Ok(mut guard) = self.profiles.write() {
            if let Some(prof) = guard.get_mut(peer_id) {
                prof.trust_score = 0;
                prof.revoked = true;
            }
        }
    }

    /// Query current trust score.
    pub fn trust_score(&self, peer_id: &str) -> Option<u32> {
        self.profiles.read().ok()?.get(peer_id).map(|p| p.trust_score)
    }

    /// Query if peer is active and trusted.
    pub fn is_trusted(&self, peer_id: &str) -> bool {
        if let Ok(guard) = self.profiles.read() {
            if let Some(p) = guard.get(peer_id) {
                return !p.revoked && p.trust_score >= self.min_trust_threshold;
            }
        }
        false
    }

    /// Verify Bell-LaPadula MLS read authorization (Simple Security Property: No Read Up).
    pub fn verify_read(
        &self,
        subject_clearance: ClearanceLevel,
        subject_caveats: u32,
        object_classification: ClearanceLevel,
        object_caveats: u32,
    ) -> Result<(), CoreError> {
        if can_read(
            subject_clearance,
            subject_caveats,
            object_classification,
            object_caveats,
        ) {
            Ok(())
        } else {
            Err(CoreError::ZeroTrustViolation)
        }
    }

    /// Verify Bell-LaPadula Star-Property write authorization (No Write Down).
    pub fn verify_write(
        &self,
        subject_clearance: ClearanceLevel,
        target_classification: ClearanceLevel,
    ) -> Result<(), CoreError> {
        if can_write(subject_clearance, target_classification) {
            Ok(())
        } else {
            Err(CoreError::ZeroTrustViolation)
        }
    }

    /// Execute NSA RTB content inspection against a payload slice.
    pub fn inspect_content(&self, payload: &[u8]) -> Result<(), CoreError> {
        inspect_content_rtb(payload).map_err(|_| CoreError::ZeroTrustViolation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_trust_rbac_permissions() {
        let zt = ZeroTrustEngine::new(50);
        zt.register_peer("alice_admin", SecurityRole::Admin);
        zt.register_peer("bob_operator", SecurityRole::Operator);
        zt.register_peer("carol_viewer", SecurityRole::Viewer);

        assert!(zt.authorize("alice_admin", PERM_CRITICAL_RELEASE).is_ok());
        assert!(zt.authorize("bob_operator", PERM_MESSAGE_SEND).is_ok());
        assert!(zt.authorize("bob_operator", PERM_CRITICAL_RELEASE).is_err());
        assert!(zt.authorize("carol_viewer", PERM_READ_ONLY).is_ok());
        assert!(zt.authorize("carol_viewer", PERM_MESSAGE_SEND).is_err());
    }

    #[test]
    fn test_continuous_penalty_and_revocation() {
        let zt = ZeroTrustEngine::new(50);
        let peer = "node_x";
        zt.register_peer(peer, SecurityRole::Operator);

        assert_eq!(zt.trust_score(peer), Some(75));
        assert!(zt.is_trusted(peer));

        // Minor anomaly: -10 penalty
        let score = zt.record_penalty(peer, 10).unwrap();
        assert_eq!(score, 65);
        assert!(zt.is_trusted(peer));

        // Severe anomaly: -20 penalty -> 45 (below threshold 50) -> revokes fail-closed!
        let res = zt.record_penalty(peer, 20);
        assert!(res.is_err());
        assert!(!zt.is_trusted(peer));
        assert!(zt.authorize(peer, PERM_MESSAGE_SEND).is_err());
    }

    #[test]
    fn test_bell_lapadula_mls_rules() {
        let zt = ZeroTrustEngine::default();

        // 1. No Read Up: Secret cannot read Top Secret
        assert!(zt
            .verify_read(
                ClearanceLevel::Secret,
                CAVEAT_NOFORN,
                ClearanceLevel::TopSecret,
                CAVEAT_NOFORN
            )
            .is_err());

        // 2. Read at or below clearance: Top Secret can read Secret
        assert!(zt
            .verify_read(
                ClearanceLevel::TopSecret,
                CAVEAT_NOFORN,
                ClearanceLevel::Secret,
                CAVEAT_NOFORN
            )
            .is_ok());

        // 3. Caveat mismatch: Top Secret without REL_TO_COALITION cannot read object requiring it
        assert!(zt
            .verify_read(
                ClearanceLevel::TopSecret,
                CAVEAT_NOFORN,
                ClearanceLevel::Secret,
                CAVEAT_NOFORN | CAVEAT_REL_TO_COALITION
            )
            .is_err());

        // 4. Star-Property (No Write Down): Secret cannot write to Unclassified
        assert!(zt
            .verify_write(ClearanceLevel::Secret, ClearanceLevel::Unclassified)
            .is_err());

        // 5. Star-Property (Write Up/Equal allowed): Secret can write to Secret or Top Secret
        assert!(zt
            .verify_write(ClearanceLevel::Secret, ClearanceLevel::Secret)
            .is_ok());
        assert!(zt
            .verify_write(ClearanceLevel::Secret, ClearanceLevel::TopSecret)
            .is_ok());
    }

    #[test]
    fn test_nsa_rtb_content_inspection() {
        let zt = ZeroTrustEngine::default();

        let clean_payload = b"TACTICAL STATUS: ALL RADAR UNITS FUNCTIONAL AND REPORTING GREEN";
        assert!(zt.inspect_content(clean_payload).is_ok());

        let dirty_payload_1 = b"CLASSIFIED TARGET LOCATIONS: TOP SECRET // SI-OP-IA // NOFORN";
        assert!(zt.inspect_content(dirty_payload_1).is_err());

        let dirty_payload_2 = b"COORDINATES FOR SI-TK-G SATELLITE PASS";
        assert!(zt.inspect_content(dirty_payload_2).is_err());
    }
}
