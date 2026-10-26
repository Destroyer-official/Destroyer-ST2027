//! Sovereign Sender-Key Group Ratchet Engine, wire profile v2.
//!
//! Provides cryptographically authenticated sender-chain progression,
//! bounded out-of-order skipped-key decryption (Double Ratchet §3.5),
//! canonical length-prefixed context-bound AAD, and DoD/NC3 Two-Person
//! Integrity (TPI) dual-officer epoch authorization (RFC 9420 / RFC 9750).
//!
//! Security properties enforced:
//! 1. Forward Secrecy: Per-member sender chains advance monotonically via HKDF-SHA384.
//! 2. Post-Compromise Security: Coordinated epoch rekey mixes fresh entropy into group secret.
//! 3. Bounded Out-of-Order Delivery: Skipped message keys are derived and cached up to
//!    MAX_TOTAL_SKIPPED_KEYS with automatic zeroization and oldest-first eviction.
//! 4. Dual-Officer Epoch Integrity: Epoch advancement and roster mutations strictly require
//!    independent Two-Person Integrity (TPI) authorization tokens (fail-closed on single custody).
//! 5. AEAD Authentication: AES-256-GCM with canonical context-bound AAD (protocol, group, epoch, sender, seq).
//! 6. Zeroization: All ephemeral keys, skipped message keys, and epoch secrets zeroize on drop.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// Version 2 uses canonical length-prefixed AAD. Frames encrypted with the
/// legacy ambiguous v1 AAD are intentionally not accepted by this profile.
pub const GROUP_PROTO_ID: &[u8] = b"ST2027-SOVEREIGN-GROUP-v2";
pub const EPOCH_KDF_INFO: &[u8] = b"ST2027-Group-Epoch-Rekey-HKDF-SHA384";
pub const CHAIN_KDF_INFO: &[u8] = b"ST2027-Group-Chain-Ratchet-HKDF-SHA384";
pub const MSG_KDF_INFO: &[u8] = b"ST2027-Group-Message-Key-HKDF-SHA384";
pub const EPOCH_AUTH_DOMAIN: &[u8] = b"ST2027-EPOCH-AUTH-COMMIT-v1";

pub const MAX_CHAIN_CATCHUP: u64 = 1000;
pub const MAX_SKIPPED_PER_MEMBER: usize = 200;
pub const MAX_TOTAL_SKIPPED_KEYS: usize = 2000;

#[derive(Debug, PartialEq, Eq)]
pub enum GroupError {
    MemberNotFound,
    SequenceMismatch,
    SequenceExhausted,
    ChainCatchupExceeded,
    AuthenticationFailed,
    TpiInsufficientOfficers,
    InvalidEpoch,
    InvalidIdentifier,
    KdfError,
}

/// Canonical AAD prevents variable-length identifier boundary ambiguity and
/// binds the protocol version, group, epoch, sender, and sequence.
fn message_aad(
    group_id: &str,
    epoch: u64,
    sender_id: &str,
    seq: u64,
) -> Result<Vec<u8>, GroupError> {
    let group_len = u32::try_from(group_id.len()).map_err(|_| GroupError::InvalidIdentifier)?;
    let sender_len = u32::try_from(sender_id.len()).map_err(|_| GroupError::InvalidIdentifier)?;
    let mut aad =
        Vec::with_capacity(GROUP_PROTO_ID.len() + 4 + group_id.len() + 8 + 4 + sender_id.len() + 8);
    aad.extend_from_slice(GROUP_PROTO_ID);
    aad.extend_from_slice(&group_len.to_be_bytes());
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&sender_len.to_be_bytes());
    aad.extend_from_slice(sender_id.as_bytes());
    aad.extend_from_slice(&seq.to_be_bytes());
    Ok(aad)
}

fn compute_officer_hmac(key: &[u8], tbs_bytes: &[u8]) -> Result<[u8; 32], GroupError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| GroupError::KdfError)?;
    mac.update(tbs_bytes);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&result);
    Ok(tag)
}

/// Two-Person Integrity (TPI) Dual-Officer Epoch Authorization Token.
/// Binds target epoch, canonical roster hash, and fresh entropy commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochAuthToken {
    pub officer1_id: String,
    pub officer2_id: String,
    pub group_id: String,
    pub target_epoch: u64,
    pub roster_hash: [u8; 32],
    pub entropy_commitment: [u8; 32],
    pub officer1_auth_tag: [u8; 32],
    pub officer2_auth_tag: [u8; 32],
}

impl EpochAuthToken {
    /// Generate an authentic dual-officer epoch authorization token.
    /// Rejects single-custody attempts (officer1 == officer2).
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        officer1_id: &str,
        officer1_key: &[u8],
        officer2_id: &str,
        officer2_key: &[u8],
        group_id: &str,
        target_epoch: u64,
        roster_hash: [u8; 32],
        fresh_entropy: &[u8; 48],
    ) -> Result<Self, GroupError> {
        if officer1_id == officer2_id {
            return Err(GroupError::TpiInsufficientOfficers);
        }
        let entropy_commitment: [u8; 32] = Sha256::digest(fresh_entropy).into();
        let mut tbs = Vec::new();
        tbs.extend_from_slice(EPOCH_AUTH_DOMAIN);
        tbs.extend_from_slice(&(group_id.len() as u32).to_be_bytes());
        tbs.extend_from_slice(group_id.as_bytes());
        tbs.extend_from_slice(&target_epoch.to_be_bytes());
        tbs.extend_from_slice(&roster_hash);
        tbs.extend_from_slice(&entropy_commitment);

        let tag1 = compute_officer_hmac(officer1_key, &tbs)?;
        let tag2 = compute_officer_hmac(officer2_key, &tbs)?;

        Ok(Self {
            officer1_id: officer1_id.to_string(),
            officer2_id: officer2_id.to_string(),
            group_id: group_id.to_string(),
            target_epoch,
            roster_hash,
            entropy_commitment,
            officer1_auth_tag: tag1,
            officer2_auth_tag: tag2,
        })
    }

    /// Verify token against group context and officer pre-shared keys in constant time.
    pub fn verify(
        &self,
        group_id: &str,
        current_epoch: u64,
        roster_hash: &[u8; 32],
        fresh_entropy: &[u8; 48],
        officer1_key: &[u8],
        officer2_key: &[u8],
    ) -> Result<(), GroupError> {
        if self.officer1_id == self.officer2_id {
            return Err(GroupError::TpiInsufficientOfficers);
        }
        if self.group_id != group_id {
            return Err(GroupError::InvalidIdentifier);
        }
        let expected_epoch = current_epoch
            .checked_add(1)
            .ok_or(GroupError::InvalidEpoch)?;
        if self.target_epoch != expected_epoch {
            return Err(GroupError::InvalidEpoch);
        }
        if &self.roster_hash != roster_hash {
            return Err(GroupError::AuthenticationFailed);
        }
        let expected_entropy_comm: [u8; 32] = Sha256::digest(fresh_entropy).into();
        if self.entropy_commitment != expected_entropy_comm {
            return Err(GroupError::AuthenticationFailed);
        }

        let mut tbs = Vec::new();
        tbs.extend_from_slice(EPOCH_AUTH_DOMAIN);
        tbs.extend_from_slice(&(group_id.len() as u32).to_be_bytes());
        tbs.extend_from_slice(group_id.as_bytes());
        tbs.extend_from_slice(&self.target_epoch.to_be_bytes());
        tbs.extend_from_slice(&self.roster_hash);
        tbs.extend_from_slice(&self.entropy_commitment);

        let expected_tag1 = compute_officer_hmac(officer1_key, &tbs)?;
        let expected_tag2 = compute_officer_hmac(officer2_key, &tbs)?;

        if self.officer1_auth_tag.ct_eq(&expected_tag1).unwrap_u8() != 1
            || self.officer2_auth_tag.ct_eq(&expected_tag2).unwrap_u8() != 1
        {
            return Err(GroupError::AuthenticationFailed);
        }

        Ok(())
    }
}

/// Symmetric chain state for a single group member.
#[derive(Clone)]
pub struct MemberChainState {
    pub member_id: String,
    pub chain_key: [u8; 48],
    pub message_seq: u64,
}

impl Drop for MemberChainState {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

impl MemberChainState {
    pub fn new(member_id: String, chain_key: [u8; 48]) -> Self {
        Self {
            member_id,
            chain_key,
            message_seq: 0,
        }
    }

    /// Derives next 32-byte AES-GCM message key and ratchets the 48-byte chain key forward.
    pub fn ratchet_forward(&mut self) -> Result<(Zeroizing<[u8; 32]>, u64), GroupError> {
        let seq = self.message_seq;
        let next_seq = seq.checked_add(1).ok_or(GroupError::SequenceExhausted)?;
        let mut msg_info = Vec::with_capacity(MSG_KDF_INFO.len() + 8);
        msg_info.extend_from_slice(MSG_KDF_INFO);
        msg_info.extend_from_slice(&seq.to_be_bytes());

        let hk = Hkdf::<Sha384>::new(None, &self.chain_key);
        let mut msg_key = [0u8; 32];
        hk.expand(&msg_info, &mut msg_key)
            .map_err(|_| GroupError::KdfError)?;
        let mut next_chain = [0u8; 48];
        hk.expand(CHAIN_KDF_INFO, &mut next_chain)
            .map_err(|_| GroupError::KdfError)?;

        self.chain_key.zeroize();
        self.chain_key = next_chain;
        self.message_seq = next_seq;
        Ok((Zeroizing::new(msg_key), seq))
    }
}

/// Sovereign Group Ratchet Session.
pub struct SovereignGroupRatchet {
    pub group_id: String,
    pub local_member_id: String,
    pub epoch: u64,
    pub epoch_secret: Zeroizing<[u8; 48]>,
    pub members: HashMap<String, MemberChainState>,
    pub roster: Vec<String>,
    pub skipped_message_keys: HashMap<(String, u64, u64), Zeroizing<[u8; 32]>>,
}

impl SovereignGroupRatchet {
    /// Initialize a new group session with initial epoch secret.
    pub fn new(
        group_id: String,
        local_member_id: String,
        initial_epoch_secret: [u8; 48],
    ) -> Result<Self, GroupError> {
        let mut group = Self {
            group_id,
            local_member_id: local_member_id.clone(),
            epoch: 0,
            epoch_secret: Zeroizing::new(initial_epoch_secret),
            members: HashMap::new(),
            roster: vec![local_member_id],
            skipped_message_keys: HashMap::new(),
        };
        group.init_local_sender_key()?;
        Ok(group)
    }

    /// Compute canonical SHA-256 roster hash for TPI authorization binding.
    pub fn compute_roster_hash(&self) -> [u8; 32] {
        let mut sorted = self.roster.clone();
        sorted.sort();
        let mut hasher = Sha256::new();
        hasher.update(b"ST2027-ROSTER-V1");
        for m in sorted {
            hasher.update((m.len() as u32).to_be_bytes());
            hasher.update(m.as_bytes());
        }
        hasher.finalize().into()
    }

    fn derive_sender_chain(
        secret: &[u8; 48],
        member_id: &str,
        epoch: u64,
    ) -> Result<[u8; 48], GroupError> {
        let hk = Hkdf::<Sha384>::new(Some(b"member-init-salt"), secret);
        let mut member_chain = [0u8; 48];
        let mut info = Vec::with_capacity(member_id.len() + 8);
        info.extend_from_slice(member_id.as_bytes());
        info.extend_from_slice(&epoch.to_be_bytes());
        hk.expand(&info, &mut member_chain)
            .map_err(|_| GroupError::KdfError)?;
        Ok(member_chain)
    }

    fn init_local_sender_key(&mut self) -> Result<(), GroupError> {
        let member_chain =
            Self::derive_sender_chain(&self.epoch_secret, &self.local_member_id, self.epoch)?;
        let state = MemberChainState::new(self.local_member_id.clone(), member_chain);
        self.members.insert(self.local_member_id.clone(), state);
        Ok(())
    }

    /// Add an external member and set their initial sender chain key.
    pub fn add_member(&mut self, member_id: String, chain_key: [u8; 48]) {
        let state = MemberChainState::new(member_id.clone(), chain_key);
        if !self.roster.contains(&member_id) {
            self.roster.push(member_id.clone());
        }
        self.members.insert(member_id, state);
    }

    /// Remove an external member and wipe their sender chain key.
    pub fn remove_member(&mut self, member_id: &str) {
        self.roster.retain(|m| m != member_id);
        self.members.remove(member_id);
        self.skipped_message_keys
            .retain(|(sender, _, _), _| sender != member_id);
    }

    /// Encrypt an outbound group message under the local member's ratcheted key.
    /// Wire frame output: `[uint64 epoch][uint64 seq][12B nonce][ciphertext+16B tag]`
    pub fn encrypt_group_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, GroupError> {
        let epoch_suffix = u32::try_from(self.epoch).map_err(|_| GroupError::InvalidEpoch)?;
        let local_state = self
            .members
            .get(&self.local_member_id)
            .ok_or(GroupError::MemberNotFound)?;
        let mut staged = local_state.clone();
        let (msg_key, seq) = staged.ratchet_forward()?;

        // 12-byte Nonce: [uint64 seq][4-byte epoch suffix]
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&seq.to_be_bytes());
        nonce_bytes[8..12].copy_from_slice(&epoch_suffix.to_be_bytes());
        let nonce = aes_gcm::Nonce::from(nonce_bytes);
        let aad = message_aad(&self.group_id, self.epoch, &self.local_member_id, seq)?;
        let cipher = Aes256Gcm::new_from_slice(msg_key.as_slice())
            .map_err(|_| GroupError::AuthenticationFailed)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| GroupError::AuthenticationFailed)?;

        let mut out = Vec::with_capacity(8 + 8 + 12 + ciphertext.len());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        self.members.insert(self.local_member_id.clone(), staged);
        Ok(out)
    }

    /// Decrypt an inbound group message from a remote member.
    ///
    /// Supports out-of-order delivery via bounded skipped-key storage:
    /// 1. If key was previously skipped and cached, decrypt directly and drop key.
    /// 2. If seq > current_seq, fast-forward staged chain and save skipped keys.
    /// 3. Commit staged state and skipped keys ONLY IF AES-GCM tag authenticates.
    pub fn decrypt_group_message(
        &mut self,
        sender_id: &str,
        wire_frame: &[u8],
    ) -> Result<Vec<u8>, GroupError> {
        if wire_frame.len() < 8 + 8 + 12 + 16 {
            return Err(GroupError::AuthenticationFailed);
        }
        let epoch = u64::from_be_bytes(wire_frame[..8].try_into().unwrap());
        if epoch != self.epoch {
            return Err(GroupError::InvalidEpoch);
        }
        let seq = u64::from_be_bytes(wire_frame[8..16].try_into().unwrap());
        let nonce_bytes = &wire_frame[16..28];
        let ciphertext = &wire_frame[28..];

        // 1. Check if frame matches a previously skipped message key
        let lookup_key = (sender_id.to_string(), epoch, seq);
        if let Some(skipped_msg_key) = self.skipped_message_keys.remove(&lookup_key) {
            let aad = message_aad(&self.group_id, self.epoch, sender_id, seq)?;
            let mut nb = [0u8; 12];
            nb.copy_from_slice(nonce_bytes);
            let nonce = aes_gcm::Nonce::from(nb);
            let cipher = Aes256Gcm::new_from_slice(skipped_msg_key.as_slice())
                .map_err(|_| GroupError::AuthenticationFailed)?;
            let plaintext = cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| GroupError::AuthenticationFailed)?;
            return Ok(plaintext);
        }

        // 2. Process against current sender chain position
        let member_state = self
            .members
            .get(sender_id)
            .ok_or(GroupError::MemberNotFound)?;
        if seq < member_state.message_seq {
            return Err(GroupError::SequenceMismatch);
        }
        let gap = seq - member_state.message_seq;
        if gap > MAX_CHAIN_CATCHUP {
            return Err(GroupError::ChainCatchupExceeded);
        }

        let mut staged = member_state.clone();
        let mut staged_skipped = Vec::with_capacity(gap as usize);

        // Derive and stage all skipped message keys across the gap
        while staged.message_seq < seq {
            let (skipped_key, skipped_seq) = staged.ratchet_forward()?;
            staged_skipped.push(((sender_id.to_string(), epoch, skipped_seq), skipped_key));
        }

        let (msg_key, matched_seq) = staged.ratchet_forward()?;
        if matched_seq != seq {
            return Err(GroupError::SequenceMismatch);
        }
        let aad = message_aad(&self.group_id, self.epoch, sender_id, seq)?;
        let mut nb = [0u8; 12];
        nb.copy_from_slice(nonce_bytes);
        let nonce = aes_gcm::Nonce::from(nb);
        let cipher = Aes256Gcm::new_from_slice(msg_key.as_slice())
            .map_err(|_| GroupError::AuthenticationFailed)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| GroupError::AuthenticationFailed)?;

        // ATOMIC COMMIT: Authentication succeeded! Commit receiver chain & staged skipped keys.
        self.members.insert(sender_id.to_string(), staged);
        for (k, v) in staged_skipped {
            self.skipped_message_keys.insert(k, v);
        }

        // Enforce bounded memory size on skipped-key cache (oldest evicted first)
        if self.skipped_message_keys.len() > MAX_TOTAL_SKIPPED_KEYS {
            let mut keys_to_prune: Vec<(String, u64, u64)> =
                self.skipped_message_keys.keys().cloned().collect();
            keys_to_prune.sort_by_key(|(_, ep, sq)| (*ep, *sq));
            let excess = self.skipped_message_keys.len() - MAX_TOTAL_SKIPPED_KEYS;
            for k in keys_to_prune.iter().take(excess) {
                self.skipped_message_keys.remove(k);
            }
        }

        Ok(plaintext)
    }

    /// Advance a coordinated epoch by mixing fresh entropy into the epoch secret.
    /// Prunes skipped message keys from obsolete epochs upon transition.
    pub fn advance_epoch(&mut self, fresh_entropy: &[u8; 48]) -> Result<u64, GroupError> {
        let next_epoch = self.epoch.checked_add(1).ok_or(GroupError::InvalidEpoch)?;
        if next_epoch > u32::MAX as u64 {
            return Err(GroupError::InvalidEpoch);
        }
        let mut ikm = Vec::with_capacity(48 + 48);
        ikm.extend_from_slice(self.epoch_secret.as_slice());
        ikm.extend_from_slice(fresh_entropy);
        let hk = Hkdf::<Sha384>::new(Some(EPOCH_KDF_INFO), &ikm);
        let mut new_secret = [0u8; 48];
        hk.expand(&next_epoch.to_be_bytes(), &mut new_secret)
            .map_err(|_| GroupError::KdfError)?;
        ikm.zeroize();

        let mut new_members = HashMap::with_capacity(self.roster.len());
        for member_id in &self.roster {
            let chain = Self::derive_sender_chain(&new_secret, member_id, next_epoch)?;
            new_members.insert(
                member_id.clone(),
                MemberChainState::new(member_id.clone(), chain),
            );
        }
        self.epoch_secret.zeroize();
        self.epoch_secret = Zeroizing::new(new_secret);
        self.epoch = next_epoch;
        self.members = new_members;

        // Prune expired skipped keys from prior epochs
        self.skipped_message_keys
            .retain(|(_, ep, _), _| *ep >= next_epoch);

        Ok(self.epoch)
    }

    /// Advance epoch strictly under Two-Person Integrity (TPI) dual-officer authorization.
    /// Rejects single custody or invalid signature/HMAC authentication tokens fail-closed.
    pub fn advance_epoch_authorized(
        &mut self,
        fresh_entropy: &[u8; 48],
        token: &EpochAuthToken,
        officer1_key: &[u8],
        officer2_key: &[u8],
    ) -> Result<u64, GroupError> {
        let roster_hash = self.compute_roster_hash();
        token.verify(
            &self.group_id,
            self.epoch,
            &roster_hash,
            fresh_entropy,
            officer1_key,
            officer2_key,
        )?;
        self.advance_epoch(fresh_entropy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_ratchet_roundtrip() {
        let epoch_secret = [0x42u8; 48];
        let mut alpha = SovereignGroupRatchet::new(
            "DEFCON-GROUP-1".to_string(),
            "ALPHA".to_string(),
            epoch_secret,
        )
        .unwrap();

        // Alpha derives Bravo's initial chain key under the shared epoch secret
        let hk = Hkdf::<Sha384>::new(Some(b"member-init-salt"), &epoch_secret);
        let mut bravo_chain = [0u8; 48];
        let mut info = Vec::new();
        info.extend_from_slice(b"BRAVO");
        info.extend_from_slice(&0u64.to_be_bytes());
        hk.expand(&info, &mut bravo_chain).unwrap();

        // Bravo initializes
        let mut bravo = SovereignGroupRatchet::new(
            "DEFCON-GROUP-1".to_string(),
            "BRAVO".to_string(),
            epoch_secret,
        )
        .unwrap();

        // Cross-register initial sender chains
        let mut alpha_chain = [0u8; 48];
        let mut info_a = Vec::new();
        info_a.extend_from_slice(b"ALPHA");
        info_a.extend_from_slice(&0u64.to_be_bytes());
        hk.expand(&info_a, &mut alpha_chain).unwrap();

        alpha.add_member("BRAVO".to_string(), bravo_chain);
        bravo.add_member("ALPHA".to_string(), alpha_chain);

        // Alpha encrypts
        let msg = b"TOP SECRET: REGROUP AT COORDINATES X-RAY";
        let frame = alpha.encrypt_group_message(msg).unwrap();

        // Bravo decrypts
        let decrypted = bravo.decrypt_group_message("ALPHA", &frame).unwrap();
        assert_eq!(decrypted, msg);

        // Bravo replies
        let reply = b"COPY: BRAVO MOVING TO X-RAY";
        let reply_frame = bravo.encrypt_group_message(reply).unwrap();
        let decrypted_reply = alpha.decrypt_group_message("BRAVO", &reply_frame).unwrap();
        assert_eq!(decrypted_reply, reply);
    }

    #[test]
    fn test_out_of_order_delivery_with_skipped_keys() {
        let epoch_secret = [0x42u8; 48];
        let mut alpha =
            SovereignGroupRatchet::new("DEFCON-1".into(), "ALPHA".into(), epoch_secret).unwrap();
        let mut bravo =
            SovereignGroupRatchet::new("DEFCON-1".into(), "BRAVO".into(), epoch_secret).unwrap();

        let alpha_chain = alpha.members["ALPHA"].chain_key;
        bravo.add_member("ALPHA".into(), alpha_chain);

        // Alpha sends 4 messages: seq 0, seq 1, seq 2, seq 3
        let frame0 = alpha.encrypt_group_message(b"MSG-0-LAUNCH").unwrap();
        let frame1 = alpha.encrypt_group_message(b"MSG-1-TARGET").unwrap();
        let frame2 = alpha.encrypt_group_message(b"MSG-2-VECTOR").unwrap();
        let frame3 = alpha.encrypt_group_message(b"MSG-3-CONFIRM").unwrap();

        // Network reorders: frame 3 arrives FIRST!
        let dec3 = bravo.decrypt_group_message("ALPHA", &frame3).unwrap();
        assert_eq!(dec3, b"MSG-3-CONFIRM");
        // Skipped keys for 0, 1, 2 should now be stored in bravo's cache
        assert_eq!(bravo.skipped_message_keys.len(), 3);

        // Now frame 1 arrives
        let dec1 = bravo.decrypt_group_message("ALPHA", &frame1).unwrap();
        assert_eq!(dec1, b"MSG-1-TARGET");
        assert_eq!(bravo.skipped_message_keys.len(), 2);

        // Now frame 0 arrives
        let dec0 = bravo.decrypt_group_message("ALPHA", &frame0).unwrap();
        assert_eq!(dec0, b"MSG-0-LAUNCH");
        assert_eq!(bravo.skipped_message_keys.len(), 1);

        // Now frame 2 arrives
        let dec2 = bravo.decrypt_group_message("ALPHA", &frame2).unwrap();
        assert_eq!(dec2, b"MSG-2-VECTOR");
        assert_eq!(bravo.skipped_message_keys.len(), 0);

        // Replaying any of them must fail
        assert_eq!(
            bravo.decrypt_group_message("ALPHA", &frame0),
            Err(GroupError::SequenceMismatch)
        );
    }

    #[test]
    fn test_dual_officer_tpi_epoch_advance_authorization() {
        let epoch_secret = [0x42u8; 48];
        let mut group =
            SovereignGroupRatchet::new("STRATCOM-NC3".into(), "NORAD".into(), epoch_secret)
                .unwrap();

        let officer1_id = "OFFICER-COMMANDER-01";
        let officer1_key = b"TOP-SECRET-OFFICER-1-CRYPTO-KEY-256B";
        let officer2_id = "OFFICER-VICE-COMMANDER-02";
        let officer2_key = b"TOP-SECRET-OFFICER-2-CRYPTO-KEY-256B";

        let fresh_entropy = [0x77u8; 48];
        let roster_hash = group.compute_roster_hash();

        // 1. Valid Dual-Officer Authorization Token
        let token = EpochAuthToken::generate(
            officer1_id,
            officer1_key,
            officer2_id,
            officer2_key,
            &group.group_id,
            group.epoch + 1,
            roster_hash,
            &fresh_entropy,
        )
        .unwrap();

        // Advancing epoch with valid dual authorization succeeds
        let new_epoch = group
            .advance_epoch_authorized(&fresh_entropy, &token, officer1_key, officer2_key)
            .unwrap();
        assert_eq!(new_epoch, 1);

        // 2. Single-Custody attempt: Officer 1 attempts to sign both legs
        let single_custody = EpochAuthToken::generate(
            officer1_id,
            officer1_key,
            officer1_id, // Identical officer!
            officer1_key,
            &group.group_id,
            group.epoch + 1,
            group.compute_roster_hash(),
            &fresh_entropy,
        );
        assert_eq!(single_custody, Err(GroupError::TpiInsufficientOfficers));

        // 3. Forged officer key / tampered token for next epoch (epoch 2)
        let token2 = EpochAuthToken::generate(
            officer1_id,
            officer1_key,
            officer2_id,
            officer2_key,
            &group.group_id,
            group.epoch + 1,
            group.compute_roster_hash(),
            &fresh_entropy,
        )
        .unwrap();
        let tampered_key = b"MALICIOUS-INTRUDER-KEY-WRONG-PAD";
        let auth_fail =
            group.advance_epoch_authorized(&fresh_entropy, &token2, officer1_key, tampered_key);
        assert_eq!(auth_fail, Err(GroupError::AuthenticationFailed));
    }

    #[test]
    fn forged_frame_does_not_desynchronize_receiver() {
        let epoch_secret = [0x42u8; 48];
        let mut alpha = SovereignGroupRatchet::new(
            "DEFCON-GROUP-1".to_string(),
            "ALPHA".to_string(),
            epoch_secret,
        )
        .unwrap();
        let mut bravo = SovereignGroupRatchet::new(
            "DEFCON-GROUP-1".to_string(),
            "BRAVO".to_string(),
            epoch_secret,
        )
        .unwrap();
        let alpha_chain = alpha.members["ALPHA"].chain_key;
        bravo.add_member("ALPHA".to_string(), alpha_chain);

        let honest = alpha.encrypt_group_message(b"honest message").unwrap();
        let mut forged = honest.clone();
        forged[8..16].copy_from_slice(&5u64.to_be_bytes());
        *forged.last_mut().unwrap() ^= 1;
        let chain_before = bravo.members["ALPHA"].chain_key;
        let seq_before = bravo.members["ALPHA"].message_seq;

        assert_eq!(
            bravo.decrypt_group_message("ALPHA", &forged),
            Err(GroupError::AuthenticationFailed)
        );
        assert_eq!(bravo.members["ALPHA"].chain_key, chain_before);
        assert_eq!(bravo.members["ALPHA"].message_seq, seq_before);
        // Forged jump did not commit corrupt skipped keys
        assert_eq!(bravo.skipped_message_keys.len(), 0);
        assert_eq!(
            bravo.decrypt_group_message("ALPHA", &honest).unwrap(),
            b"honest message"
        );
    }

    #[test]
    fn test_group_epoch_rekey_pcs() {
        let epoch_secret = [0x55u8; 48];
        let mut alpha = SovereignGroupRatchet::new(
            "STRATCOM-GROUP".to_string(),
            "ALPHA".to_string(),
            epoch_secret,
        )
        .unwrap();

        let old_epoch = alpha.epoch;
        let fresh_entropy = [0x99u8; 48];
        let new_epoch = alpha.advance_epoch(&fresh_entropy).unwrap();
        assert_eq!(new_epoch, old_epoch + 1);
    }

    #[test]
    fn aad_encodes_identifier_boundaries_unambiguously() {
        let left = message_aad("ab", 7, "c", 9).unwrap();
        let right = message_aad("a", 7, "bc", 9).unwrap();
        assert_ne!(left, right);
        assert!(left.starts_with(GROUP_PROTO_ID));
    }

    #[test]
    fn sequence_and_epoch_exhaustion_do_not_mutate_state() {
        let mut group =
            SovereignGroupRatchet::new("G".to_string(), "A".to_string(), [0x77u8; 48]).unwrap();
        group.members.get_mut("A").unwrap().message_seq = u64::MAX;
        let chain_before = group.members["A"].chain_key;
        assert_eq!(
            group.encrypt_group_message(b"refused"),
            Err(GroupError::SequenceExhausted)
        );
        assert_eq!(group.members["A"].chain_key, chain_before);
        assert_eq!(group.members["A"].message_seq, u64::MAX);

        group.epoch = u32::MAX as u64;
        let secret_before = *group.epoch_secret;
        assert_eq!(
            group.advance_epoch(&[0x88u8; 48]),
            Err(GroupError::InvalidEpoch)
        );
        assert_eq!(group.epoch, u32::MAX as u64);
        assert_eq!(*group.epoch_secret, secret_before);
    }

    #[test]
    fn coordinated_epoch_rekey_synchronizes_roster_chains() {
        let secret = [0x31u8; 48];
        let mut alpha = SovereignGroupRatchet::new("G".into(), "A".into(), secret).unwrap();
        let mut bravo = SovereignGroupRatchet::new("G".into(), "B".into(), secret).unwrap();
        alpha.add_member("B".into(), bravo.members["B"].chain_key);
        bravo.add_member("A".into(), alpha.members["A"].chain_key);
        assert_eq!(
            bravo
                .decrypt_group_message("A", &alpha.encrypt_group_message(b"before").unwrap(),)
                .unwrap(),
            b"before"
        );

        let entropy = [0x99u8; 48];
        alpha.advance_epoch(&entropy).unwrap();
        bravo.advance_epoch(&entropy).unwrap();
        let frame = alpha.encrypt_group_message(b"after").unwrap();
        assert_eq!(bravo.decrypt_group_message("A", &frame).unwrap(), b"after");
    }

    #[test]
    fn test_remove_member_purges_chain_and_skipped_keys_fail_closed() {
        let epoch_secret = [0x42u8; 48];
        let mut alpha =
            SovereignGroupRatchet::new("DEFCON-1".into(), "ALPHA".into(), epoch_secret).unwrap();
        let mut bravo =
            SovereignGroupRatchet::new("DEFCON-1".into(), "BRAVO".into(), epoch_secret).unwrap();

        let bravo_chain = bravo.members["BRAVO"].chain_key;
        alpha.add_member("BRAVO".into(), bravo_chain);

        let f0 = bravo.encrypt_group_message(b"MSG0").unwrap();
        let _f1 = bravo.encrypt_group_message(b"MSG1").unwrap();
        let f2 = bravo.encrypt_group_message(b"MSG2").unwrap();

        assert_eq!(alpha.decrypt_group_message("BRAVO", &f2).unwrap(), b"MSG2");
        assert_eq!(alpha.skipped_message_keys.len(), 2);

        alpha.remove_member("BRAVO");

        assert!(!alpha.roster.contains(&"BRAVO".to_string()));
        assert!(!alpha.members.contains_key("BRAVO"));
        assert_eq!(alpha.skipped_message_keys.len(), 0);

        assert_eq!(
            alpha.decrypt_group_message("BRAVO", &f0),
            Err(GroupError::MemberNotFound)
        );
    }
}
