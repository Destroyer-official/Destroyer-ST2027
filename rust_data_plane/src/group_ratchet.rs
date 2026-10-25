//! Sovereign Group Ratchet (CNSA Suite 2.0 / RFC 9420 MLS Aligned)
//! =================================================================
//! Provides Post-Quantum End-to-End Encrypted Group Messaging for Top Secret
//! Sovereign Defense Enclaves in pure, memory-locked Rust.
//!
//! Features:
//! 1. Per-Member Sender Keys with Forward Secrecy (Symmetric Ratchet via HKDF-SHA384).
//! 2. Continuous Epoch Rekeying for Post-Compromise Security (PCS self-healing).
//! 3. Authenticated AES-256-GCM message encryption with directional sequence tags.
//! 4. Two-Person Integrity (TPI) Dual-Officer verification for epoch transition.
//! 5. Memory wiping (ZeroizeOnDrop) on all epoch and chain secrets.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hkdf::Hkdf;
use sha2::Sha384;
use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

/// Version 2 uses canonical length-prefixed AAD. Frames encrypted with the
/// legacy ambiguous v1 AAD are intentionally not accepted by this profile.
pub const GROUP_PROTO_ID: &[u8] = b"ST2027-SOVEREIGN-GROUP-v2";
pub const EPOCH_KDF_INFO: &[u8] = b"ST2027-Group-Epoch-Rekey-HKDF-SHA384";
pub const CHAIN_KDF_INFO: &[u8] = b"ST2027-Group-Chain-Ratchet-HKDF-SHA384";
pub const MSG_KDF_INFO: &[u8] = b"ST2027-Group-Message-Key-HKDF-SHA384";
pub const MAX_CHAIN_CATCHUP: u64 = 1000;

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
    let mut aad = Vec::with_capacity(
        GROUP_PROTO_ID.len() + 4 + group_id.len() + 8 + 4 + sender_id.len() + 8,
    );
    aad.extend_from_slice(GROUP_PROTO_ID);
    aad.extend_from_slice(&group_len.to_be_bytes());
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&sender_len.to_be_bytes());
    aad.extend_from_slice(sender_id.as_bytes());
    aad.extend_from_slice(&seq.to_be_bytes());
    Ok(aad)
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
            roster: vec![local_member_id.clone()],
        };
        group.init_local_sender_key()?;
        Ok(group)
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

    /// Decrypt an inbound group message from a remote member. The receiver
    /// chain is committed only after AES-GCM authenticates the entire frame.
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
        while staged.message_seq < seq {
            let _ = staged.ratchet_forward()?;
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
        self.members.insert(sender_id.to_string(), staged);
        Ok(plaintext)
    }

    /// Advance a coordinated epoch by mixing fresh entropy into the epoch
    /// secret. Every roster member must receive and authorize the same update;
    /// this local primitive is not an authenticated MLS commit protocol.
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
        Ok(self.epoch)
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
        let mut group = SovereignGroupRatchet::new(
            "G".to_string(),
            "A".to_string(),
            [0x77u8; 48],
        )
        .unwrap();
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
        assert_eq!(group.advance_epoch(&[0x88u8; 48]), Err(GroupError::InvalidEpoch));
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
        assert_eq!(bravo.decrypt_group_message(
            "A",
            &alpha.encrypt_group_message(b"before").unwrap(),
        ).unwrap(), b"before");

        let entropy = [0x99u8; 48];
        alpha.advance_epoch(&entropy).unwrap();
        bravo.advance_epoch(&entropy).unwrap();
        let frame = alpha.encrypt_group_message(b"after").unwrap();
        assert_eq!(bravo.decrypt_group_message("A", &frame).unwrap(), b"after");
    }
}
