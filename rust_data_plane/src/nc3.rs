//! NC3 (Nuclear Command, Control, and Communications) Operations.
//!
//! Enforces DoD Directive 5210.41M (Two-Person Rule / No-Lone-Zone) and
//! FIPS 204 ML-DSA-87 dual-officer authentication for Emergency Action
//! Messages (EAM). Also provides the NC3 Safety Gate scanner that blocks
//! single-officer nuclear directives from leaking through routine conversational chat.

use crate::auth::{Mldsa87SigningKey, Mldsa87VerifyingKey};
use crate::ct::ct_eq;
use crate::policy::{CoreError, MLDSA87_PK, MLDSA87_SIG};

/// Cryptographic domain separation string for NC3 Emergency Action Messages.
pub const NC3_EAM_DOMAIN: &[u8] = b"DESTROYER-ST2027-NC3-EAM";

/// Maximum allowable freshness window for an EAM directive (120 seconds).
pub const EAM_FRESHNESS_WINDOW_SECS: u64 = 120;

/// NC3 Safety Gate classified & nuclear directive trigger keywords.
/// Routine chat messages containing any of these keywords are blocked fail-closed
/// unless routed through the authenticated dual-custody NC3 pipeline.
pub const NC3_KEYWORDS: [&[u8]; 15] = [
    b"launch code",
    b"nuclear strike",
    b"defcon 1",
    b"emergency action message",
    b"nuclear release",
    b"weapons release",
    b"strategic strike",
    b"icbm launch",
    b"slbm launch",
    b"nuclear warhead",
    b"permissive action link",
    b"pal code",
    b"looking glass",
    b"nightwatch",
    b"tacamo",
];

/// Scan a message for unauthorized NC3 nuclear directive keywords in routine traffic.
///
/// Returns `Ok(())` if the message is clean.
/// Returns `Err(keyword)` matching the detected indicator to prevent single-officer execution.
pub fn check_nc3_safety_gate(message: &[u8]) -> Result<(), &'static str> {
    let len = message.len();
    for &kw in &NC3_KEYWORDS {
        let kw_len = kw.len();
        if len >= kw_len {
            for i in 0..=len - kw_len {
                let slice = &message[i..i + kw_len];
                let matches = slice
                    .iter()
                    .zip(kw.iter())
                    .all(|(&b, &k)| b.to_ascii_lowercase() == k);
                if matches {
                    let s = match kw {
                        b"launch code" => "launch code",
                        b"nuclear strike" => "nuclear strike",
                        b"defcon 1" => "defcon 1",
                        b"emergency action message" => "emergency action message",
                        b"nuclear release" => "nuclear release",
                        b"weapons release" => "weapons release",
                        b"strategic strike" => "strategic strike",
                        b"icbm launch" => "icbm launch",
                        b"slbm launch" => "slbm launch",
                        b"nuclear warhead" => "nuclear warhead",
                        b"permissive action link" => "permissive action link",
                        b"pal code" => "pal code",
                        b"looking glass" => "looking glass",
                        b"nightwatch" => "nightwatch",
                        _ => "tacamo",
                    };
                    return Err(s);
                }
            }
        }
    }
    Ok(())
}

/// Verify that two officer verifying key bytes satisfy the DoD Two-Person Rule.
///
/// Refuses identical keys (single-custody attempt) in constant time.
pub fn verify_two_person_rule(vk1_bytes: &[u8], vk2_bytes: &[u8]) -> Result<(), CoreError> {
    if vk1_bytes.len() != MLDSA87_PK || vk2_bytes.len() != MLDSA87_PK {
        return Err(CoreError::Malformed);
    }
    if ct_eq(vk1_bytes, vk2_bytes) {
        return Err(CoreError::AuthRequired);
    }
    Ok(())
}

/// Two-Person Authenticated Emergency Action Message Directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EamDirective {
    pub directive_text: Vec<u8>,
    pub officer1_sig: Vec<u8>,
    pub officer2_sig: Vec<u8>,
    pub timestamp_secs: u64,
}

impl EamDirective {
    /// Serialize EAM directive to a compact binary wire representation:
    /// `[ts: 8B BE][sig1: 4627B][sig2: 4627B][text_len: 4B BE][text: variable]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let text_len = self.directive_text.len() as u32;
        let mut out = Vec::with_capacity(8 + (MLDSA87_SIG * 2) + 4 + self.directive_text.len());
        out.extend_from_slice(&self.timestamp_secs.to_be_bytes());
        out.extend_from_slice(&self.officer1_sig);
        out.extend_from_slice(&self.officer2_sig);
        out.extend_from_slice(&text_len.to_be_bytes());
        out.extend_from_slice(&self.directive_text);
        out
    }

    /// Deserialize EAM directive from wire representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        const MIN_LEN: usize = 8 + (MLDSA87_SIG * 2) + 4;
        if bytes.len() < MIN_LEN {
            return Err(CoreError::Malformed);
        }
        let ts_bytes: [u8; 8] = bytes[0..8].try_into().map_err(|_| CoreError::Malformed)?;
        let timestamp_secs = u64::from_be_bytes(ts_bytes);

        let sig1 = bytes[8..8 + MLDSA87_SIG].to_vec();
        let sig2 = bytes[8 + MLDSA87_SIG..8 + (MLDSA87_SIG * 2)].to_vec();

        let len_offset = 8 + (MLDSA87_SIG * 2);
        let text_len_bytes: [u8; 4] = bytes[len_offset..len_offset + 4]
            .try_into()
            .map_err(|_| CoreError::Malformed)?;
        let text_len = u32::from_be_bytes(text_len_bytes) as usize;

        if bytes.len() != len_offset + 4 + text_len {
            return Err(CoreError::Malformed);
        }

        let directive_text = bytes[len_offset + 4..].to_vec();
        Ok(Self {
            directive_text,
            officer1_sig: sig1,
            officer2_sig: sig2,
            timestamp_secs,
        })
    }
}

/// Construct a binding payload covering `timestamp_secs || directive_text` for signature.
pub fn compute_eam_tbs(directive_text: &[u8], timestamp_secs: u64) -> Vec<u8> {
    let mut tbs = Vec::with_capacity(8 + directive_text.len());
    tbs.extend_from_slice(&timestamp_secs.to_be_bytes());
    tbs.extend_from_slice(directive_text);
    tbs
}

/// Create an authentic dual-officer signed NC3 Emergency Action Message.
pub fn create_eam(
    directive: &[u8],
    sk1: &Mldsa87SigningKey,
    sk2: &Mldsa87SigningKey,
) -> Result<EamDirective, CoreError> {
    let vk1_bytes = sk1.verifying_bytes();
    let vk2_bytes = sk2.verifying_bytes();
    verify_two_person_rule(&vk1_bytes, &vk2_bytes)?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::OsRandom)?
        .as_secs();

    let tbs = compute_eam_tbs(directive, now_secs);
    let sig1 = sk1.sign(NC3_EAM_DOMAIN, &tbs);
    let sig2 = sk2.sign(NC3_EAM_DOMAIN, &tbs);

    Ok(EamDirective {
        directive_text: directive.to_vec(),
        officer1_sig: sig1,
        officer2_sig: sig2,
        timestamp_secs: now_secs,
    })
}

/// Verify an NC3 EAM directive against two enrolled officer keys.
///
/// Checks:
/// 1. Two distinct keys (Two-Person Rule / No-Lone-Zone)
/// 2. Valid ML-DSA-87 signature 1 from Officer 1
/// 3. Valid ML-DSA-87 signature 2 from Officer 2
/// 4. Freshness window check (fail-closed if outside `window_secs`, if window_secs > 0)
pub fn verify_eam(
    directive: &EamDirective,
    vk1: &Mldsa87VerifyingKey,
    vk2: &Mldsa87VerifyingKey,
    max_age_secs: Option<u64>,
) -> Result<(), CoreError> {
    let vk1_bytes = vk1.to_bytes();
    let vk2_bytes = vk2.to_bytes();
    verify_two_person_rule(&vk1_bytes, &vk2_bytes)?;

    if let Some(max_age) = max_age_secs {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CoreError::OsRandom)?
            .as_secs();
        if now_secs < directive.timestamp_secs || (now_secs - directive.timestamp_secs) > max_age {
            return Err(CoreError::Stale);
        }
    }

    let tbs = compute_eam_tbs(&directive.directive_text, directive.timestamp_secs);
    vk1.verify(NC3_EAM_DOMAIN, &tbs, &directive.officer1_sig)?;
    vk2.verify(NC3_EAM_DOMAIN, &tbs, &directive.officer2_sig)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_gate_blocks_nuclear_keywords() {
        assert!(check_nc3_safety_gate(b"routine tactical update coordinates 38N").is_ok());
        assert_eq!(
            check_nc3_safety_gate(b"execute strategic strike on grid 4"),
            Err("strategic strike")
        );
        assert_eq!(
            check_nc3_safety_gate(b"Verify PAL code immediately"),
            Err("pal code")
        );
        assert_eq!(
            check_nc3_safety_gate(b"DEFCON 1 posture ordered"),
            Err("defcon 1")
        );
        assert_eq!(
            check_nc3_safety_gate(b"Emergency Action Message arriving"),
            Err("emergency action message")
        );
    }

    #[test]
    fn safety_gate_case_insensitive() {
        assert_eq!(
            check_nc3_safety_gate(b"AUTHORIZE NUCLEAR RELEASE NOW"),
            Err("nuclear release")
        );
    }

    #[test]
    fn two_person_rule_blocks_same_officer() {
        let (_sk1, vk1) = Mldsa87SigningKey::generate().unwrap();
        let vk1_bytes = vk1.to_bytes();
        assert_eq!(
            verify_two_person_rule(&vk1_bytes, &vk1_bytes),
            Err(CoreError::AuthRequired)
        );

        let (_, vk2) = Mldsa87SigningKey::generate().unwrap();
        let vk2_bytes = vk2.to_bytes();
        assert!(verify_two_person_rule(&vk1_bytes, &vk2_bytes).is_ok());
    }

    #[test]
    fn eam_create_verify_and_wire_roundtrip() {
        let (sk1, vk1) = Mldsa87SigningKey::generate().unwrap();
        let (sk2, vk2) = Mldsa87SigningKey::generate().unwrap();

        let directive_text = b"EXECUTE RETALIATORY STRIKE PLAN FOXTROT // TARGET OMEGA";
        let eam = create_eam(directive_text, &sk1, &sk2).expect("create_eam");

        // Verify succeeds with fresh window
        verify_eam(&eam, &vk1, &vk2, Some(120)).expect("verify_eam");

        // Wire round-trip
        let wire = eam.to_bytes();
        let parsed = EamDirective::from_bytes(&wire).expect("from_bytes");
        assert_eq!(parsed, eam);

        // Verification on parsed struct succeeds
        verify_eam(&parsed, &vk1, &vk2, Some(120)).expect("verify parsed");

        // Tampered directive text fails verification
        let mut tampered = eam.clone();
        tampered.directive_text = b"EXECUTE UNAUTHORIZED STRIKE".to_vec();
        assert!(verify_eam(&tampered, &vk1, &vk2, None).is_err());

        // Single officer custody fails verification
        assert_eq!(
            verify_eam(&eam, &vk1, &vk1, None),
            Err(CoreError::AuthRequired)
        );
    }
}
