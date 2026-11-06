//! NC3 (Nuclear Command, Control, and Communications) Operations.
//!
//! Enforces DoD Directive 5210.41M (Two-Person Rule / No-Lone-Zone) and
//! FIPS 204 ML-DSA-87 dual-officer authentication for Emergency Action
//! Messages (EAM). Also provides the NC3 Safety Gate scanner that blocks
//! single-officer nuclear directives from leaking through routine conversational chat.

use crate::auth::{sign_with_hsm, HsmSession, Mldsa87SigningKey, Mldsa87VerifyingKey};
use crate::ct::ct_eq;
use crate::policy::{CoreError, MLDSA87_PK, MLDSA87_SIG};
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;

/// Magic header for hardware dual-smartcard Emergency Action Message wire packages.
pub const HW_EAM_MAGIC: &[u8; 10] = b"ST-EAM-HW2";

/// Maximum allowable temporal skew between physical smartcard hardware signatures (2.0 seconds).
pub const MAX_TEMPORAL_SKEW_MILLIS: u64 = 2000;

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

/// Create an authentic dual-officer signed NC3 Emergency Action Message using physical hardware PKCS#11 tokens.
///
/// Under DoD Directive 5210.41M (Two-Person Rule / Two-Person Integrity), signing
/// requires two physically distinct hardware tokens (e.g. dual YubiKeys, dual Luna partitions,
/// or hardware PAL conduits).
pub fn create_eam_with_hw_tokens(
    directive: &[u8],
    session1: &Session,
    key_handle1: ObjectHandle,
    vk1_bytes: &[u8],
    session2: &Session,
    key_handle2: ObjectHandle,
    vk2_bytes: &[u8],
) -> Result<EamDirective, CoreError> {
    verify_two_person_rule(vk1_bytes, vk2_bytes)?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::OsRandom)?
        .as_secs();

    let tbs = compute_eam_tbs(directive, now_secs);

    let sig1 = sign_with_hsm(session1, key_handle1, &tbs).map_err(|_| CoreError::AuthRequired)?;
    let sig2 = sign_with_hsm(session2, key_handle2, &tbs).map_err(|_| CoreError::AuthRequired)?;

    Ok(EamDirective {
        directive_text: directive.to_vec(),
        officer1_sig: sig1,
        officer2_sig: sig2,
        timestamp_secs: now_secs,
    })
}

/// Enforce production split-knowledge doctrine.
///
/// In production, disk-based synthetic JSON signatures are strictly prohibited fail-closed
/// to eliminate accidental unauthorized command release without physical smartcards.
pub fn enforce_production_split_knowledge_doctrine(
    is_production: bool,
    used_disk_signatures: bool,
) -> Result<(), CoreError> {
    if is_production && used_disk_signatures {
        eprintln!(
            "SECURITY VIOLATION: DISK-BASED SIMULATED SIGNATURES PROHIBITED IN PRODUCTION. \
Physical split-knowledge hardware smartcards (dual YubiKeys or hardware PAL conduit) \
required under DoD 5210.41M. Accidental command release prevention enforced."
        );
        return Err(CoreError::AuthRequired);
    }
    Ok(())
}

/// Compute the canonical FIPS 202 SHA3-512 directive hash for hardware-enforced TPI.
///
/// Formula: DirectiveHash = SHA3-512(Timestamp || Target || ActionPayload)
/// where Timestamp is encoded as 8-byte big-endian u64.
pub fn compute_directive_hash(
    timestamp_secs: u64,
    target: &str,
    action_payload: &[u8],
) -> [u8; 64] {
    use sha3::{Digest, Sha3_512};
    let mut hasher = Sha3_512::new();
    hasher.update(&timestamp_secs.to_be_bytes());
    hasher.update(target.as_bytes());
    hasher.update(action_payload);
    let res = hasher.finalize();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&res);
    hash
}

/// Validate that two hardware tokens generated signatures within the temporal hardware window.
///
/// Under DoD 5210.41M / 2026 TPI doctrine, concurrent split-knowledge authorization requires:
/// 1. Concurrent Execution: |t1 - t2| <= max_skew_millis (default: 2000 ms / 2.0s).
/// 2. Absolute Freshness: |now - signature_time| <= max_age_secs (default: 120s).
pub fn validate_temporal_hardware_window(
    t1_millis: u64,
    t2_millis: u64,
    now_millis: u64,
    max_skew_millis: u64,
    max_age_secs: u64,
) -> Result<(), CoreError> {
    let skew = if t1_millis >= t2_millis {
        t1_millis - t2_millis
    } else {
        t2_millis - t1_millis
    };

    if skew > max_skew_millis {
        eprintln!(
            "TEMPORAL HARDWARE SKEW VIOLATION: Smartcard signatures generated {skew}ms apart (max allowable: {max_skew_millis}ms). Accidental release / delayed reuse refused fail-closed."
        );
        return Err(CoreError::Stale);
    }

    let max_age_millis = max_age_secs.saturating_mul(1000);
    let signature_time = (t1_millis + t2_millis) / 2;
    if now_millis < signature_time {
        if signature_time - now_millis > 5000 {
            return Err(CoreError::Stale);
        }
    } else if now_millis - signature_time > max_age_millis {
        eprintln!(
            "EAM FRESHNESS VIOLATION: EAM signature age {}ms exceeds {}ms TTL window",
            now_millis - signature_time,
            max_age_millis
        );
        return Err(CoreError::Stale);
    }

    Ok(())
}

/// Enforce physical smartcard token separation across independent CCID readers.
///
/// Checks:
/// 1. Verifying key separation (vk1 != vk2) in constant time.
/// 2. CCID Reader / Slot separation (slot1 != slot2).
/// 3. Physical token serial separation (serial1 != serial2) when available from silicon.
pub fn validate_smartcard_separation(
    slot1: usize,
    slot2: usize,
    serial1: Option<&str>,
    serial2: Option<&str>,
    vk1_bytes: &[u8],
    vk2_bytes: &[u8],
) -> Result<(), CoreError> {
    // Key separation
    verify_two_person_rule(vk1_bytes, vk2_bytes)?;

    // Slot separation
    if slot1 == slot2 {
        eprintln!(
            "TPI HARDWARE REFUSAL: Reader/Slot 1 and Reader/Slot 2 are identical ({slot1}). Two independent CCID smartcard readers required under DoD 5210.41M."
        );
        return Err(CoreError::AuthRequired);
    }

    // Token serial separation
    if let (Some(s1), Some(s2)) = (serial1, serial2) {
        if !s1.is_empty() && !s2.is_empty() && s1.trim() == s2.trim() {
            eprintln!(
                "TPI HARDWARE REFUSAL: Smartcard serial numbers are identical ('{s1}'). Same physical token cannot be used in both readers."
            );
            return Err(CoreError::AuthRequired);
        }
    }

    Ok(())
}

/// High-Assurance Hardware-Enforced Two-Person Integrity EAM Wire Package.
///
/// Contains dual ML-DSA-87 signatures from distinct CCID smartcards,
/// hardware millisecond timestamps, canonical SHA3-512 directive hash,
/// and target/action payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareEamPackage {
    pub timestamp_secs: u64,
    pub t1_millis: u64,
    pub t2_millis: u64,
    pub target: String,
    pub action_payload: Vec<u8>,
    pub directive_hash: [u8; 64],
    pub officer1_vk: Vec<u8>,
    pub officer1_sig: Vec<u8>,
    pub officer2_vk: Vec<u8>,
    pub officer2_sig: Vec<u8>,
}

impl HardwareEamPackage {
    /// Serialize package to high-assurance binary wire format:
    /// `[MAGIC: 10B][ts: 8B][t1: 8B][t2: 8B][hash: 64B][vk1: 2592B][sig1: 4627B][vk2: 2592B][sig2: 4627B][target_len: 4B][target][payload_len: 4B][payload]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let target_bytes = self.target.as_bytes();
        let mut out = Vec::with_capacity(
            10 + 8
                + 8
                + 8
                + 64
                + MLDSA87_PK
                + MLDSA87_SIG
                + MLDSA87_PK
                + MLDSA87_SIG
                + 4
                + target_bytes.len()
                + 4
                + self.action_payload.len(),
        );
        out.extend_from_slice(HW_EAM_MAGIC);
        out.extend_from_slice(&self.timestamp_secs.to_be_bytes());
        out.extend_from_slice(&self.t1_millis.to_be_bytes());
        out.extend_from_slice(&self.t2_millis.to_be_bytes());
        out.extend_from_slice(&self.directive_hash);
        out.extend_from_slice(&self.officer1_vk);
        out.extend_from_slice(&self.officer1_sig);
        out.extend_from_slice(&self.officer2_vk);
        out.extend_from_slice(&self.officer2_sig);
        out.extend_from_slice(&(target_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(target_bytes);
        out.extend_from_slice(&(self.action_payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.action_payload);
        out
    }

    /// Deserialize package from wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        const MIN_LEN: usize = 10 + 8 + 8 + 8 + 64 + (MLDSA87_PK * 2) + (MLDSA87_SIG * 2) + 4 + 4;
        if bytes.len() < MIN_LEN {
            return Err(CoreError::Malformed);
        }
        if &bytes[0..10] != HW_EAM_MAGIC {
            return Err(CoreError::Malformed);
        }
        let mut offset = 10;

        let timestamp_secs = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CoreError::Malformed)?,
        );
        offset += 8;
        let t1_millis = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CoreError::Malformed)?,
        );
        offset += 8;
        let t2_millis = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CoreError::Malformed)?,
        );
        offset += 8;

        let mut directive_hash = [0u8; 64];
        directive_hash.copy_from_slice(&bytes[offset..offset + 64]);
        offset += 64;

        let officer1_vk = bytes[offset..offset + MLDSA87_PK].to_vec();
        offset += MLDSA87_PK;
        let officer1_sig = bytes[offset..offset + MLDSA87_SIG].to_vec();
        offset += MLDSA87_SIG;

        let officer2_vk = bytes[offset..offset + MLDSA87_PK].to_vec();
        offset += MLDSA87_PK;
        let officer2_sig = bytes[offset..offset + MLDSA87_SIG].to_vec();
        offset += MLDSA87_SIG;

        let target_len = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CoreError::Malformed)?,
        ) as usize;
        offset += 4;
        if bytes.len() < offset + target_len + 4 {
            return Err(CoreError::Malformed);
        }
        let target = std::str::from_utf8(&bytes[offset..offset + target_len])
            .map_err(|_| CoreError::Malformed)?
            .to_string();
        offset += target_len;

        let payload_len = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CoreError::Malformed)?,
        ) as usize;
        offset += 4;
        if bytes.len() != offset + payload_len {
            return Err(CoreError::Malformed);
        }
        let action_payload = bytes[offset..offset + payload_len].to_vec();

        Ok(Self {
            timestamp_secs,
            t1_millis,
            t2_millis,
            target,
            action_payload,
            directive_hash,
            officer1_vk,
            officer1_sig,
            officer2_vk,
            officer2_sig,
        })
    }

    /// Full cryptographic verification of hardware EAM package.
    pub fn verify(
        &self,
        now_millis: u64,
        max_skew_millis: u64,
        max_age_secs: u64,
    ) -> Result<(), CoreError> {
        // 1. Two-person rule separation
        verify_two_person_rule(&self.officer1_vk, &self.officer2_vk)?;

        // 2. Validate temporal hardware window (|t1 - t2| <= max_skew_millis)
        validate_temporal_hardware_window(
            self.t1_millis,
            self.t2_millis,
            now_millis,
            max_skew_millis,
            max_age_secs,
        )?;

        // 3. Recompute and verify DirectiveHash = SHA3-512(Timestamp || Target || ActionPayload)
        let expected_hash =
            compute_directive_hash(self.timestamp_secs, &self.target, &self.action_payload);
        if !ct_eq(&self.directive_hash, &expected_hash) {
            eprintln!("NC3 DIRECTIVE HASH MISMATCH: SHA3-512 integrity check failed");
            return Err(CoreError::AuthRequired);
        }

        // 4. Verify Officer 1 ML-DSA-87 signature over DirectiveHash
        let vk1 = Mldsa87VerifyingKey::from_bytes(&self.officer1_vk)?;
        vk1.verify(NC3_EAM_DOMAIN, &self.directive_hash, &self.officer1_sig)?;

        // 5. Verify Officer 2 ML-DSA-87 signature over DirectiveHash
        let vk2 = Mldsa87VerifyingKey::from_bytes(&self.officer2_vk)?;
        vk2.verify(NC3_EAM_DOMAIN, &self.directive_hash, &self.officer2_sig)?;

        Ok(())
    }

    /// Full cryptographic verification of hardware EAM package with trusted officer roster enforcement.
    pub fn verify_with_roster(
        &self,
        roster: &OfficerRoster,
        now_millis: u64,
        max_skew_millis: u64,
        max_age_secs: u64,
    ) -> Result<(), CoreError> {
        if !roster.is_authorized(&self.officer1_vk) {
            eprintln!("NC3 ROSTER REJECTION: Officer 1 verifying key is not in authorized officer roster");
            return Err(CoreError::AuthRequired);
        }
        if !roster.is_authorized(&self.officer2_vk) {
            eprintln!("NC3 ROSTER REJECTION: Officer 2 verifying key is not in authorized officer roster");
            return Err(CoreError::AuthRequired);
        }
        self.verify(now_millis, max_skew_millis, max_age_secs)
    }

    /// Convert to classic EamDirective for backwards compatibility.
    pub fn to_classic_eam_directive(&self) -> EamDirective {
        EamDirective {
            directive_text: self.action_payload.clone(),
            officer1_sig: self.officer1_sig.clone(),
            officer2_sig: self.officer2_sig.clone(),
            timestamp_secs: self.timestamp_secs,
        }
    }

    /// JSON diagnostic summary.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"magic\":\"{}\",\"timestamp_secs\":{},\"t1_millis\":{},\"t2_millis\":{},\"temporal_skew_ms\":{},\"target\":\"{}\",\"directive_hash\":\"{}\",\"officer1_vk\":\"{}\",\"officer1_sig\":\"{}\",\"officer2_vk\":\"{}\",\"officer2_sig\":\"{}\",\"action_payload_hex\":\"{}\"}}",
            std::str::from_utf8(HW_EAM_MAGIC).unwrap_or("ST-EAM-HW2"),
            self.timestamp_secs,
            self.t1_millis,
            self.t2_millis,
            if self.t1_millis >= self.t2_millis { self.t1_millis - self.t2_millis } else { self.t2_millis - self.t1_millis },
            self.target,
            self.directive_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            self.officer1_vk.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            self.officer1_sig.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            self.officer2_vk.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            self.officer2_sig.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            self.action_payload.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        )
    }
}

/// Authorized military officer profile in the trusted roster.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OfficerRecord {
    pub callsign: String,
    pub role: String,
    pub verifying_key_hex: String,
    pub authorized: bool,
}

/// Cryptographically pinned roster of authorized NC3 release officers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OfficerRoster {
    pub officers: Vec<OfficerRecord>,
}

impl OfficerRoster {
    pub fn new() -> Self {
        Self { officers: Vec::new() }
    }

    pub fn add_officer(&mut self, callsign: &str, role: &str, vk_bytes: &[u8], authorized: bool) {
        let hex = vk_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        self.officers.push(OfficerRecord {
            callsign: callsign.to_string(),
            role: role.to_string(),
            verifying_key_hex: hex,
            authorized,
        });
    }

    pub fn is_authorized(&self, vk_bytes: &[u8]) -> bool {
        let hex = vk_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        self.officers.iter().any(|o| o.authorized && o.verifying_key_hex.eq_ignore_ascii_case(&hex))
    }

    pub fn from_json(json_str: &str) -> Result<Self, CoreError> {
        let mut roster = Self::new();
        let parts: Vec<&str> = json_str.split('{').collect();
        for part in parts {
            if !part.contains("verifying_key_hex") && !part.contains("vk") {
                continue;
            }
            let mut vk_hex = String::new();
            let mut callsign = "OFFICER".to_string();
            let mut role = "OPERATOR".to_string();
            let mut authorized = true;

            for token in part.split(',') {
                let kv: Vec<&str> = token.split(':').collect();
                if kv.len() >= 2 {
                    let k = kv[0].trim().trim_matches(|c| c == '"' || c == '\'' || c == ' ' || c == '\n' || c == '\r');
                    let v = kv[1].trim().trim_matches(|c| c == '"' || c == '\'' || c == '}' || c == ']' || c == ' ' || c == '\n' || c == '\r');
                    match k {
                        "verifying_key_hex" | "vk_hex" | "vk" => vk_hex = v.to_string(),
                        "callsign" => callsign = v.to_string(),
                        "role" => role = v.to_string(),
                        "authorized" => authorized = v == "true" || v == "1",
                        _ => {}
                    }
                }
            }
            if !vk_hex.is_empty() {
                roster.officers.push(OfficerRecord {
                    callsign,
                    role,
                    verifying_key_hex: vk_hex,
                    authorized,
                });
            }
        }
        if roster.officers.is_empty() {
            return Err(CoreError::Malformed);
        }
        Ok(roster)
    }

    pub fn to_json(&self) -> String {
        let mut out = String::from("[\n");
        for (i, o) in self.officers.iter().enumerate() {
            out.push_str(&format!(
                "  {{\"callsign\": \"{}\", \"role\": \"{}\", \"verifying_key_hex\": \"{}\", \"authorized\": {}}}{}\n",
                o.callsign, o.role, o.verifying_key_hex, o.authorized,
                if i + 1 < self.officers.len() { "," } else { "" }
            ));
        }
        out.push(']');
        out
    }
}

/// Execute physical dual-smartcard split-knowledge ceremony across two independent PKCS#11 sessions.
pub fn execute_dual_smartcard_ceremony(
    session1: &HsmSession,
    key_handle1: ObjectHandle,
    vk1_bytes: &[u8],
    session2: &HsmSession,
    key_handle2: ObjectHandle,
    vk2_bytes: &[u8],
    target: &str,
    action_payload: &[u8],
    max_skew_millis: u64,
) -> Result<HardwareEamPackage, CoreError> {
    validate_smartcard_separation(
        session1.slot_index(),
        session2.slot_index(),
        session1.token_serial(),
        session2.token_serial(),
        vk1_bytes,
        vk2_bytes,
    )?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::OsRandom)?
        .as_secs();

    let directive_hash = compute_directive_hash(now_secs, target, action_payload);

    let t1_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::OsRandom)?
        .as_millis() as u64;
    let sig1 = session1
        .sign(key_handle1, &directive_hash)
        .map_err(|_| CoreError::AuthRequired)?;

    let t2_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::OsRandom)?
        .as_millis() as u64;
    let sig2 = session2
        .sign(key_handle2, &directive_hash)
        .map_err(|_| CoreError::AuthRequired)?;

    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::OsRandom)?
        .as_millis() as u64;

    validate_temporal_hardware_window(
        t1_millis,
        t2_millis,
        now_millis,
        max_skew_millis,
        EAM_FRESHNESS_WINDOW_SECS,
    )?;

    Ok(HardwareEamPackage {
        timestamp_secs: now_secs,
        t1_millis,
        t2_millis,
        target: target.to_string(),
        action_payload: action_payload.to_vec(),
        directive_hash,
        officer1_vk: vk1_bytes.to_vec(),
        officer1_sig: sig1,
        officer2_vk: vk2_bytes.to_vec(),
        officer2_sig: sig2,
    })
}

/// Mock physical CCID smartcard token representation for CI/automated testing.
pub struct MockSmartcardToken {
    pub slot_index: usize,
    pub serial: String,
    pub pin: String,
    pub signing_key: Mldsa87SigningKey,
}

/// Mock high-assurance dual-smartcard workstation simulator.
pub struct MockDualSmartcardSimulator {
    pub token1: MockSmartcardToken,
    pub token2: MockSmartcardToken,
    pub simulated_skew_millis: u64,
}

impl MockDualSmartcardSimulator {
    pub fn new(pin1: &str, pin2: &str) -> Result<Self, CoreError> {
        let (sk1, _) = Mldsa87SigningKey::generate()?;
        let (sk2, _) = Mldsa87SigningKey::generate()?;

        Ok(Self {
            token1: MockSmartcardToken {
                slot_index: 0,
                serial: "NORAD-CCID-READER1-CARD01".to_string(),
                pin: pin1.to_string(),
                signing_key: sk1,
            },
            token2: MockSmartcardToken {
                slot_index: 1,
                serial: "STRATCOM-CCID-READER2-CARD02".to_string(),
                pin: pin2.to_string(),
                signing_key: sk2,
            },
            simulated_skew_millis: 50,
        })
    }

    pub fn with_skew_millis(mut self, skew_millis: u64) -> Self {
        self.simulated_skew_millis = skew_millis;
        self
    }

    pub fn with_token1_slot(mut self, slot: usize) -> Self {
        self.token1.slot_index = slot;
        self
    }

    pub fn with_token2_slot(mut self, slot: usize) -> Self {
        self.token2.slot_index = slot;
        self
    }

    pub fn with_token1_serial(mut self, serial: &str) -> Self {
        self.token1.serial = serial.to_string();
        self
    }

    pub fn with_token2_serial(mut self, serial: &str) -> Self {
        self.token2.serial = serial.to_string();
        self
    }

    pub fn sign_eam(
        &self,
        target: &str,
        action_payload: &[u8],
        entered_pin1: &str,
        entered_pin2: &str,
        max_skew_millis: u64,
    ) -> Result<HardwareEamPackage, CoreError> {
        // Enforce physical separation
        validate_smartcard_separation(
            self.token1.slot_index,
            self.token2.slot_index,
            Some(&self.token1.serial),
            Some(&self.token2.serial),
            &self.token1.signing_key.verifying_bytes(),
            &self.token2.signing_key.verifying_bytes(),
        )?;

        // Validate PIN 1 (constant time)
        if !ct_eq(entered_pin1.as_bytes(), self.token1.pin.as_bytes()) {
            eprintln!("TPI PIN FAILURE: Officer 1 smartcard PIN authentication failed");
            return Err(CoreError::AuthRequired);
        }

        // Validate PIN 2 (constant time)
        if !ct_eq(entered_pin2.as_bytes(), self.token2.pin.as_bytes()) {
            eprintln!("TPI PIN FAILURE: Officer 2 smartcard PIN authentication failed");
            return Err(CoreError::AuthRequired);
        }

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CoreError::OsRandom)?
            .as_secs();

        let directive_hash = compute_directive_hash(now_secs, target, action_payload);

        let t1_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CoreError::OsRandom)?
            .as_millis() as u64;
        let sig1 = self
            .token1
            .signing_key
            .sign(NC3_EAM_DOMAIN, &directive_hash);

        let t2_millis = t1_millis + self.simulated_skew_millis;
        let sig2 = self
            .token2
            .signing_key
            .sign(NC3_EAM_DOMAIN, &directive_hash);

        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CoreError::OsRandom)?
            .as_millis() as u64;

        validate_temporal_hardware_window(
            t1_millis,
            t2_millis,
            now_millis,
            max_skew_millis,
            EAM_FRESHNESS_WINDOW_SECS,
        )?;

        Ok(HardwareEamPackage {
            timestamp_secs: now_secs,
            t1_millis,
            t2_millis,
            target: target.to_string(),
            action_payload: action_payload.to_vec(),
            directive_hash,
            officer1_vk: self.token1.signing_key.verifying_bytes().to_vec(),
            officer1_sig: sig1,
            officer2_vk: self.token2.signing_key.verifying_bytes().to_vec(),
            officer2_sig: sig2,
        })
    }
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

    #[test]
    fn production_split_knowledge_doctrine_enforcement() {
        // Lab mode allows simulated disk signatures
        assert!(enforce_production_split_knowledge_doctrine(false, true).is_ok());
        assert!(enforce_production_split_knowledge_doctrine(false, false).is_ok());
        // Production strictly forbids disk signatures
        assert_eq!(
            enforce_production_split_knowledge_doctrine(true, true),
            Err(CoreError::AuthRequired)
        );
        // Production allows hardware token signatures (non-disk)
        assert!(enforce_production_split_knowledge_doctrine(true, false).is_ok());
    }

    #[test]
    fn directive_hash_sha3_512_computation() {
        let ts = 1731000000u64;
        let target = "PENTAGON_NMCC";
        let payload = b"EXECUTE ALPHA TARGET 01";
        let h = compute_directive_hash(ts, target, payload);
        assert_eq!(h.len(), 64);

        // Verify repeatability
        let h2 = compute_directive_hash(ts, target, payload);
        assert_eq!(h, h2);

        // Verify sensitivity
        let h_tampered = compute_directive_hash(ts + 1, target, payload);
        assert_ne!(h, h_tampered);
    }

    #[test]
    fn temporal_hardware_window_validation() {
        let now = 1731000050000u64;
        // Skew = 150ms <= 2000ms: PASS
        assert!(
            validate_temporal_hardware_window(1731000050000, 1731000050150, now, 2000, 120).is_ok()
        );

        // Skew = 2500ms > 2000ms: FAIL (temporal skew exceeded)
        assert_eq!(
            validate_temporal_hardware_window(1731000050000, 1731000052500, now, 2000, 120),
            Err(CoreError::Stale)
        );

        // Stale timestamp (age = 200s > 120s TTL): FAIL
        assert_eq!(
            validate_temporal_hardware_window(
                1731000000000,
                1731000000100,
                1731000250000,
                2000,
                120
            ),
            Err(CoreError::Stale)
        );
    }

    #[test]
    fn smartcard_separation_checks() {
        let (_sk1, vk1) = Mldsa87SigningKey::generate().unwrap();
        let (_sk2, vk2) = Mldsa87SigningKey::generate().unwrap();
        let vk1_bytes = vk1.to_bytes();
        let vk2_bytes = vk2.to_bytes();

        // Valid separation: slot 0 != slot 1, diff serials, diff keys
        assert!(validate_smartcard_separation(
            0,
            1,
            Some("CARD1"),
            Some("CARD2"),
            &vk1_bytes,
            &vk2_bytes
        )
        .is_ok());

        // Same slot: FAIL
        assert_eq!(
            validate_smartcard_separation(
                0,
                0,
                Some("CARD1"),
                Some("CARD2"),
                &vk1_bytes,
                &vk2_bytes
            ),
            Err(CoreError::AuthRequired)
        );

        // Same serial: FAIL
        assert_eq!(
            validate_smartcard_separation(
                0,
                1,
                Some("CARD-CLONE"),
                Some("CARD-CLONE"),
                &vk1_bytes,
                &vk2_bytes
            ),
            Err(CoreError::AuthRequired)
        );

        // Same key: FAIL
        assert_eq!(
            validate_smartcard_separation(
                0,
                1,
                Some("CARD1"),
                Some("CARD2"),
                &vk1_bytes,
                &vk1_bytes
            ),
            Err(CoreError::AuthRequired)
        );
    }

    #[test]
    fn mock_dual_smartcard_simulator_flow() {
        let sim = MockDualSmartcardSimulator::new("123456", "654321").expect("simulator setup");
        let target = "STRATCOM_BURROWS";
        let payload = b"DIRECTIVE-DEFCON-1-AUTHORIZATION-PAYLOAD";

        // Clean signing
        let pkg = sim
            .sign_eam(target, payload, "123456", "654321", 2000)
            .expect("sign_eam");
        assert_eq!(pkg.target, target);
        assert_eq!(pkg.action_payload, payload);

        // Verify package succeeds
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        pkg.verify(now_millis, 2000, 120).expect("verify package");

        // Wire roundtrip
        let wire = pkg.to_bytes();
        let parsed = HardwareEamPackage::from_bytes(&wire).expect("from_bytes");
        assert_eq!(parsed, pkg);
        parsed
            .verify(now_millis, 2000, 120)
            .expect("verify parsed wire");

        // Wrong PIN 1 fails
        assert_eq!(
            sim.sign_eam(target, payload, "000000", "654321", 2000),
            Err(CoreError::AuthRequired)
        );

        // Wrong PIN 2 fails
        assert_eq!(
            sim.sign_eam(target, payload, "123456", "000000", 2000),
            Err(CoreError::AuthRequired)
        );

        // Simulated Skew Violation (> 2.0s) fails
        let sim_skewed = sim.with_skew_millis(2500);
        assert_eq!(
            sim_skewed.sign_eam(target, payload, "123456", "654321", 2000),
            Err(CoreError::Stale)
        );

        // Same reader slot collision fails
        let mut sim_same_slot = MockDualSmartcardSimulator::new("123456", "654321").unwrap();
        sim_same_slot.token2.slot_index = 0; // Collusion attempt
        assert_eq!(
            sim_same_slot.sign_eam(target, payload, "123456", "654321", 2000),
            Err(CoreError::AuthRequired)
        );

        // Tampered payload fails verification
        let mut tampered_pkg = pkg.clone();
        tampered_pkg.action_payload = b"TAMPERED-UNAUTHORIZED-PAYLOAD".to_vec();
        assert_eq!(
            tampered_pkg.verify(now_millis, 2000, 120),
            Err(CoreError::AuthRequired)
        );

        // Tampered target fails verification
        let mut tampered_target_pkg = pkg.clone();
        tampered_target_pkg.target = "UNAUTHORIZED_TARGET".to_string();
        assert_eq!(
            tampered_target_pkg.verify(now_millis, 2000, 120),
            Err(CoreError::AuthRequired)
        );
    }

    #[test]
    fn officer_roster_verification_flow() {
        let sim = MockDualSmartcardSimulator::new("123456", "654321").expect("simulator setup");
        let target = "STRATCOM_BURROWS";
        let payload = b"DIRECTIVE-DEFCON-1-AUTHORIZATION-PAYLOAD";
        let pkg = sim
            .sign_eam(target, payload, "123456", "654321", 2000)
            .expect("sign_eam");
        let now_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // 1. Authorized roster with both officers passes
        let mut roster = OfficerRoster::new();
        roster.add_officer("MAJOR_ALICE", "AUTH_OFFICER", &pkg.officer1_vk, true);
        roster.add_officer("CAPTAIN_BOB", "AUTH_OFFICER", &pkg.officer2_vk, true);

        pkg.verify_with_roster(&roster, now_millis, 2000, 120).expect("verify with valid roster");

        // JSON roundtrip
        let json_rep = roster.to_json();
        let parsed_roster = OfficerRoster::from_json(&json_rep).expect("from_json");
        pkg.verify_with_roster(&parsed_roster, now_millis, 2000, 120).expect("verify with parsed roster");

        // 2. Roster missing Officer 2 fails closed
        let mut incomplete_roster = OfficerRoster::new();
        incomplete_roster.add_officer("MAJOR_ALICE", "AUTH_OFFICER", &pkg.officer1_vk, true);
        assert_eq!(
            pkg.verify_with_roster(&incomplete_roster, now_millis, 2000, 120),
            Err(CoreError::AuthRequired)
        );

        // 3. Officer 2 marked unauthorized fails closed
        let mut revoked_roster = OfficerRoster::new();
        revoked_roster.add_officer("MAJOR_ALICE", "AUTH_OFFICER", &pkg.officer1_vk, true);
        revoked_roster.add_officer("CAPTAIN_BOB", "AUTH_OFFICER", &pkg.officer2_vk, false);
        assert_eq!(
            pkg.verify_with_roster(&revoked_roster, now_millis, 2000, 120),
            Err(CoreError::AuthRequired)
        );
    }
}
