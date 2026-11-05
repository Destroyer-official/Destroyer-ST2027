//! Project-specific fresh-KEM ratchet inspired by SPQR/Triple Ratchet.
//!
//! This is not an implementation of Signal SPQR or the Triple Ratchet
//! specification, and no equivalent security or interoperability is claimed.
//! Reference behavior mirrors `double_ratchet.py` v2 semantics and
//! `secure_transmit_2027.py::rehandshake`, but WITHOUT any legacy mode:
//! there is no v1 KEM-reuse path in this crate, so "downgrade to reuse"
//! is unrepresentable. Every DH step performs a FRESH hybrid encapsulation
//! (fresh ML-KEM-1024 + fresh ephemeral P-384 against the peer's
//! advertised bundle); any fresh-KEM failure is a hard error (strict abort
//! is the only behavior — no flag exists to disable it).
//!
//! Construction (per step, role-separated epochs):
//! ```text
//! (ml_ct, pq_hybrid, eph_p) = encaps(peer_p384_pub, peer_ek)  // fresh both halves
//! root_n   = HKDF-SHA384(root_{n-1} || pq_hybrid, ROOT || epoch)
//! chain_n  = HKDF-SHA384(chain_{n-1} || pq_hybrid, CHAIN || epoch)
//! msg_key  = HKDF-SHA384(chain_n, b"msg" || seq)
//! ```
//! Old halves are zeroized on rotation. Skipped-key store is bounded
//! (`MAX_SKIPPED_KEYS`, Signal default 1000); over-budget fails closed.
//!
//! Research: Dodis et al. 2025/078 Triple Ratchet / Signal SPQR motivates
//! fresh-KEM healing. This implementation performs a fresh encapsulation on
//! every step, but cadence alone does not establish stronger or equivalent
//! post-compromise security; the composition requires independent review.

use hkdf::Hkdf;
use sha2::Sha384;
use std::collections::VecDeque;
use zeroize::{Zeroize, Zeroizing};

use crate::frame::{
    InBandEpochRekeyPayload, AUTH_TAG_16_LEN, IN_BAND_REKEY_PAYLOAD_LEN, MLKEM1024_CT_LEN,
};
use crate::kem::{EphemeralKeys, HYBRID_SS, MLKEM_CT, MLKEM_PK, P384_PK};
use crate::policy::{
    CoreError, DOMAIN_EPOCH_AUTH_KEY, DOMAIN_EPOCH_RATCHET_ROOT, DOMAIN_RATCHET_CHAIN,
    DOMAIN_RATCHET_ROOT, MAX_SKIPPED_KEYS, MLKEM1024_PK, ROLLOVER_BYTE_THRESHOLD,
    ROLLOVER_PACKET_THRESHOLD,
};

/// One sending step's fresh material for the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatchetStep {
    /// Our fresh ephemeral P-384 public (97 bytes, uncompressed SEC1).
    pub eph_p_pub: [u8; P384_PK],
    /// Fresh ML-KEM ciphertext (1568 bytes) for this step.
    pub ml_ct: Vec<u8>,
    /// Our NEXT advertised bundle for the following step.
    pub next_p_pub: [u8; P384_PK],
    /// Next encapsulation key bytes (1568).
    pub next_ek: Vec<u8>,
    /// Epoch number (monotonic).
    pub epoch: u64,
}

pub const ADVERT_WIRE_LEN: usize = 8 + P384_PK + MLKEM_PK; // 1673 bytes
pub const RATCHET_STEP_WIRE_LEN: usize = 8 + P384_PK + MLKEM_CT + P384_PK + MLKEM_PK; // 3338 bytes

/// Advertised hybrid public key bundle for the next KEM encapsulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertBundle {
    pub p_pub: [u8; P384_PK],
    pub ek: Vec<u8>,
    pub epoch: u64,
}

impl AdvertBundle {
    pub fn new(p_pub: [u8; P384_PK], ek: Vec<u8>, epoch: u64) -> Result<Self, CoreError> {
        if ek.len() != MLKEM_PK {
            return Err(CoreError::Malformed);
        }
        Ok(Self { p_pub, ek, epoch })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ADVERT_WIRE_LEN);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.p_pub);
        out.extend_from_slice(&self.ek);
        out
    }

    pub fn from_bytes(slice: &[u8]) -> Result<Self, CoreError> {
        if slice.len() != ADVERT_WIRE_LEN {
            return Err(CoreError::Malformed);
        }
        let epoch = u64::from_be_bytes(slice[0..8].try_into().map_err(|_| CoreError::Malformed)?);
        let mut p_pub = [0u8; P384_PK];
        p_pub.copy_from_slice(&slice[8..8 + P384_PK]);
        let ek = slice[8 + P384_PK..8 + P384_PK + MLKEM_PK].to_vec();
        Ok(Self { p_pub, ek, epoch })
    }
}

impl RatchetStep {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RATCHET_STEP_WIRE_LEN);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.eph_p_pub);
        out.extend_from_slice(&self.ml_ct);
        out.extend_from_slice(&self.next_p_pub);
        out.extend_from_slice(&self.next_ek);
        out
    }

    pub fn from_bytes(slice: &[u8]) -> Result<Self, CoreError> {
        if slice.len() != RATCHET_STEP_WIRE_LEN {
            return Err(CoreError::Malformed);
        }
        let mut offset = 0;
        let epoch = u64::from_be_bytes(
            slice[offset..offset + 8]
                .try_into()
                .map_err(|_| CoreError::Malformed)?,
        );
        offset += 8;

        let mut eph_p_pub = [0u8; P384_PK];
        eph_p_pub.copy_from_slice(&slice[offset..offset + P384_PK]);
        offset += P384_PK;

        let ml_ct = slice[offset..offset + MLKEM_CT].to_vec();
        offset += MLKEM_CT;

        let mut next_p_pub = [0u8; P384_PK];
        next_p_pub.copy_from_slice(&slice[offset..offset + P384_PK]);
        offset += P384_PK;

        let next_ek = slice[offset..offset + MLKEM_PK].to_vec();

        Ok(Self {
            eph_p_pub,
            ml_ct,
            next_p_pub,
            next_ek,
            epoch,
        })
    }
}

pub const REKEY_MSG_ADVERT: u8 = 0x01;
pub const REKEY_MSG_STEP: u8 = 0x02;
pub const REKEY_MSG_CONFIRM: u8 = 0x03;

/// Wire envelope for in-band Continuous Epoch Ratchet exchanges.
#[derive(Debug, Clone)]
pub enum RekeyMessage {
    Advert(AdvertBundle),
    Step(RatchetStep),
    Confirm { epoch: u64, auth_tag: [u8; 32] },
}

impl RekeyMessage {
    pub fn to_wire(&self) -> Vec<u8> {
        match self {
            RekeyMessage::Advert(adv) => {
                let mut out = Vec::with_capacity(1 + ADVERT_WIRE_LEN);
                out.push(REKEY_MSG_ADVERT);
                out.extend_from_slice(&adv.to_bytes());
                out
            }
            RekeyMessage::Step(step) => {
                let mut out = Vec::with_capacity(1 + RATCHET_STEP_WIRE_LEN);
                out.push(REKEY_MSG_STEP);
                out.extend_from_slice(&step.to_bytes());
                out
            }
            RekeyMessage::Confirm { epoch, auth_tag } => {
                let mut out = Vec::with_capacity(1 + 8 + 32);
                out.push(REKEY_MSG_CONFIRM);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(auth_tag);
                out
            }
        }
    }

    pub fn from_wire(slice: &[u8]) -> Result<Self, CoreError> {
        if slice.is_empty() {
            return Err(CoreError::Malformed);
        }
        match slice[0] {
            REKEY_MSG_ADVERT => {
                let adv = AdvertBundle::from_bytes(&slice[1..])?;
                Ok(RekeyMessage::Advert(adv))
            }
            REKEY_MSG_STEP => {
                let step = RatchetStep::from_bytes(&slice[1..])?;
                Ok(RekeyMessage::Step(step))
            }
            REKEY_MSG_CONFIRM => {
                if slice.len() != 1 + 8 + 32 {
                    return Err(CoreError::Malformed);
                }
                let epoch =
                    u64::from_be_bytes(slice[1..9].try_into().map_err(|_| CoreError::Malformed)?);
                let mut auth_tag = [0u8; 32];
                auth_tag.copy_from_slice(&slice[9..41]);
                Ok(RekeyMessage::Confirm { epoch, auth_tag })
            }
            _ => Err(CoreError::Malformed),
        }
    }
}

/// PCS ratchet state. Key halves zeroized on rotation and on drop
/// (manual Drop; EphemeralKeys has its own wiping Drop).
pub struct PcsRatchet {
    root: [u8; 32],
    chain: [u8; 32],
    epoch: u64,
    send_seq: u64,
    /// Current advertised bundle (rotated every step, never reused).
    bundle: EphemeralKeys,
    /// Last received advertised bundle from the peer.
    peer_bundle: Option<AdvertBundle>,
    /// Skipped message keys (bounded).
    skipped: VecDeque<([u8; 32], u64)>,
    /// Automatic rollover packet counter (threshold N = 10,000).
    packets_transmitted: u64,
    /// Automatic rollover transmitted byte counter (threshold M = 10 MB).
    bytes_transmitted: u64,
    /// Rollover packet threshold (default ROLLOVER_PACKET_THRESHOLD = 10,000).
    rollover_packet_threshold: u64,
    /// Rollover byte threshold (default ROLLOVER_BYTE_THRESHOLD = 10 MB = 10,485,760 bytes).
    rollover_byte_threshold: u64,
}

impl Drop for PcsRatchet {
    fn drop(&mut self) {
        self.root.zeroize();
        self.chain.zeroize();
        for (k, _) in self.skipped.iter_mut() {
            k.zeroize();
        }
        // `bundle` drops next via its own wiping Drop.
    }
}

impl PcsRatchet {
    /// Initialize from a 32-byte KEX session key (from `kex_auth`).
    pub fn new(session_key: &[u8; 32]) -> Result<Self, CoreError> {
        let mut root = [0u8; 32];
        root.copy_from_slice(session_key);
        let chain = hkdf32(&root, DOMAIN_RATCHET_CHAIN, b"init")?;
        let bundle = EphemeralKeys::generate().map_err(|_| CoreError::OsRandom)?;
        Ok(Self {
            root,
            chain,
            epoch: 0,
            send_seq: 0,
            bundle,
            peer_bundle: None,
            skipped: VecDeque::new(),
            packets_transmitted: 0,
            bytes_transmitted: 0,
            rollover_packet_threshold: ROLLOVER_PACKET_THRESHOLD,
            rollover_byte_threshold: ROLLOVER_BYTE_THRESHOLD,
        })
    }

    /// Currently advertised `(p384_pub, ek)` pair.
    pub fn advertise(&self) -> ([u8; P384_PK], Vec<u8>) {
        (self.bundle.p_public, self.bundle.ml_ek.clone())
    }

    /// Currently advertised bundle for the peer.
    pub fn advertise_bundle(&self) -> AdvertBundle {
        AdvertBundle {
            p_pub: self.bundle.p_public,
            ek: self.bundle.ml_ek.clone(),
            epoch: self.epoch,
        }
    }

    /// Set or update the peer's advertised bundle.
    pub fn set_peer_bundle(&mut self, bundle: AdvertBundle) {
        self.peer_bundle = Some(bundle);
    }

    /// Peer's current advertised bundle, if received.
    pub fn peer_bundle(&self) -> Option<&AdvertBundle> {
        self.peer_bundle.as_ref()
    }

    /// Autonomous send step using the stored peer advertised bundle.
    pub fn send_step_auto(&mut self) -> Result<(RatchetStep, [u8; 32]), CoreError> {
        let b = self.peer_bundle.as_ref().ok_or(CoreError::AuthRequired)?;
        let p_pub = b.p_pub;
        let ek = b.ek.clone();
        self.send_step(&p_pub, &ek)
    }

    /// Receiving step that also captures the peer's next advertised bundle.
    pub fn receive_step_with_advert(&mut self, step: &RatchetStep) -> Result<[u8; 32], CoreError> {
        let msg_key = self.receive_step(&step.eph_p_pub, &step.ml_ct)?;
        self.peer_bundle = Some(AdvertBundle {
            p_pub: step.next_p_pub,
            ek: step.next_ek.clone(),
            epoch: step.epoch,
        });
        Ok(msg_key)
    }

    /// Derive an epoch confirmation tag bound to the epoch and new chain.
    pub fn compute_confirm_tag(&self, epoch: u64) -> Result<[u8; 32], CoreError> {
        let mut info = Vec::with_capacity(16);
        info.extend_from_slice(b"ST2027-CONFIRM");
        info.extend_from_slice(&epoch.to_be_bytes());
        hkdf32(&self.chain, DOMAIN_RATCHET_CHAIN, &info)
    }

    /// Current root key (for audit/test verification).
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Current chain key (for audit/test verification).
    pub fn chain(&self) -> &[u8; 32] {
        &self.chain
    }

    /// Derive an AEAD FrameKey from the current chain secret.
    pub fn current_frame_key(&self) -> Result<crate::aead::FrameKey, CoreError> {
        let mut info = Vec::with_capacity(DOMAIN_RATCHET_CHAIN.len() + 8);
        info.extend_from_slice(DOMAIN_RATCHET_CHAIN);
        info.extend_from_slice(&self.epoch.to_be_bytes());
        let fk_bytes = hkdf32(&self.chain, DOMAIN_RATCHET_CHAIN, &info)?;
        Ok(crate::aead::FrameKey::from_bytes(fk_bytes))
    }

    /// Epoch (monotonic step counter).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Record transmitted packet and payload bytes towards automatic epoch rollover.
    pub fn note_transmission(&mut self, payload_bytes: usize) {
        self.packets_transmitted = self.packets_transmitted.saturating_add(1);
        self.bytes_transmitted = self.bytes_transmitted.saturating_add(payload_bytes as u64);
    }

    /// True when transmission counters reach N = 10,000 packets or M = 10 MB.
    pub fn needs_rollover(&self) -> bool {
        self.packets_transmitted >= self.rollover_packet_threshold
            || self.bytes_transmitted >= self.rollover_byte_threshold
    }

    /// Configure custom packet and byte rollover thresholds (for testing or profile override).
    pub fn set_rollover_thresholds(&mut self, packets: u64, bytes: u64) {
        self.rollover_packet_threshold = packets;
        self.rollover_byte_threshold = bytes;
    }

    /// Inspect current (packets_transmitted, bytes_transmitted).
    pub fn rollover_counters(&self) -> (u64, u64) {
        (self.packets_transmitted, self.bytes_transmitted)
    }

    /// Reset transmission counters to zero.
    pub fn reset_rollover_counters(&mut self) {
        self.packets_transmitted = 0;
        self.bytes_transmitted = 0;
    }

    /// Compute 16-byte HMAC-SHA384 authentication tag covering (epoch || ct) under root key.
    pub fn compute_epoch_auth_tag(
        root: &[u8; 32],
        epoch: u32,
        ct: &[u8; MLKEM1024_CT_LEN],
    ) -> Result<[u8; AUTH_TAG_16_LEN], CoreError> {
        use hmac::{Hmac, Mac};
        type HmacSha384 = Hmac<sha2::Sha384>;
        let auth_key = hkdf32(root, DOMAIN_EPOCH_AUTH_KEY, b"ST2027-EPOCH-REKEY-AUTH")?;
        let mut mac = <HmacSha384 as hmac::digest::KeyInit>::new_from_slice(&auth_key)
            .map_err(|_| CoreError::Malformed)?;
        mac.update(&epoch.to_be_bytes());
        mac.update(ct);
        let full_tag = mac.finalize().into_bytes();
        let mut tag = [0u8; AUTH_TAG_16_LEN];
        tag.copy_from_slice(&full_tag[..AUTH_TAG_16_LEN]);
        Ok(tag)
    }

    /// Constant-time verification of 16-byte HMAC-SHA384 authentication tag.
    pub fn verify_epoch_auth_tag(
        root: &[u8; 32],
        epoch: u32,
        ct: &[u8; MLKEM1024_CT_LEN],
        tag: &[u8; AUTH_TAG_16_LEN],
    ) -> Result<(), CoreError> {
        use subtle::ConstantTimeEq;
        let expected = Self::compute_epoch_auth_tag(root, epoch, ct)?;
        if expected.ct_eq(tag).into() {
            Ok(())
        } else {
            Err(CoreError::BadSignature)
        }
    }

    /// HKDF-SHA384 root derivation:
    /// `RootKey_{epoch+1} = HKDF-SHA384(RootKey_{epoch}, ML-KEM-1024-Decaps(ct))`
    fn hkdf_epoch_root(
        current_root: &[u8; 32],
        ml_ss: &[u8],
        next_epoch: u32,
    ) -> Result<[u8; 32], CoreError> {
        let hk = Hkdf::<Sha384>::new(Some(current_root), ml_ss);
        let mut info = Vec::with_capacity(DOMAIN_EPOCH_RATCHET_ROOT.len() + 4);
        info.extend_from_slice(DOMAIN_EPOCH_RATCHET_ROOT);
        info.extend_from_slice(&next_epoch.to_be_bytes());
        let mut next_root = [0u8; 32];
        hk.expand(&info, &mut next_root)
            .map_err(|_| CoreError::Malformed)?;
        Ok(next_root)
    }

    /// Build a fresh Frame Type 0x07 IN_BAND_EPOCH_REKEY payload (1588 bytes)
    /// using peer's advertised ML-KEM-1024 encapsulation key.
    ///
    /// Payload format: `EpochIndex (u32) || Ephemeral_MLKEM_Ciphertext (1568 bytes) || AuthTag (16 bytes)`.
    /// Enforces: `RootKey_{epoch+1} = HKDF-SHA384(RootKey_{epoch}, ML-KEM-1024-Decaps(ct))`.
    /// Immediately volatile-zeroizes old root, old chain, shared secret, and intermediate keys.
    pub fn build_in_band_epoch_rekey(
        &mut self,
        peer_ml_ek: &[u8],
    ) -> Result<[u8; IN_BAND_REKEY_PAYLOAD_LEN], CoreError> {
        if peer_ml_ek.len() != MLKEM1024_PK {
            return Err(CoreError::Malformed);
        }
        let next_epoch = (self.epoch as u32)
            .checked_add(1)
            .ok_or(CoreError::Oversize)?;
        let (ct_vec, ml_ss) =
            crate::kem::encapsulate_mlkem(peer_ml_ek).map_err(|_| CoreError::Malformed)?;
        if ct_vec.len() != MLKEM1024_CT_LEN {
            return Err(CoreError::Malformed);
        }
        let mut ct = [0u8; MLKEM1024_CT_LEN];
        ct.copy_from_slice(&ct_vec);

        // Compute 16-byte AuthTag bound to (epoch || ct) under current root
        let tag = Self::compute_epoch_auth_tag(&self.root, next_epoch, &ct)?;

        // Advance root key: RootKey_{epoch+1} = HKDF-SHA384(RootKey_{epoch}, ss)
        let new_root = Self::hkdf_epoch_root(&self.root, ml_ss.as_slice(), next_epoch)?;
        let new_chain = hkdf32(&new_root, DOMAIN_RATCHET_CHAIN, &next_epoch.to_be_bytes())?;
        let fresh_bundle = EphemeralKeys::generate().map_err(|_| CoreError::OsRandom)?;

        // Volatile zeroization of old epoch secrets
        self.root.zeroize();
        self.chain.zeroize();
        self.root = new_root;
        self.chain = new_chain;
        self.epoch = next_epoch as u64;
        self.bundle = fresh_bundle;
        self.reset_rollover_counters();

        let mut payload = [0u8; IN_BAND_REKEY_PAYLOAD_LEN];
        payload[..4].copy_from_slice(&next_epoch.to_be_bytes());
        payload[4..4 + MLKEM1024_CT_LEN].copy_from_slice(&ct);
        payload[4 + MLKEM1024_CT_LEN..].copy_from_slice(&tag);
        Ok(payload)
    }

    /// Process and verify an inbound Frame Type 0x07 IN_BAND_EPOCH_REKEY payload (1588 bytes).
    ///
    /// Verifies 16-byte AuthTag in constant-time BEFORE any state mutation.
    /// Decapsulates ML-KEM-1024 ciphertext with local private key.
    /// Evolves root key: `RootKey_{epoch+1} = HKDF-SHA384(RootKey_{epoch}, ML-KEM-1024-Decaps(ct))`.
    /// Immediately volatile-zeroizes old root, old chain, decapsulation key, and intermediate secrets.
    pub fn process_in_band_epoch_rekey(&mut self, payload: &[u8]) -> Result<[u8; 32], CoreError> {
        let parsed = InBandEpochRekeyPayload::from_bytes(payload)?;
        let expected_epoch = (self.epoch as u32)
            .checked_add(1)
            .ok_or(CoreError::Oversize)?;
        if parsed.epoch != expected_epoch {
            return Err(CoreError::Stale);
        }

        // Verify 16-byte AuthTag constant-time under current root BEFORE state mutation or decaps
        Self::verify_epoch_auth_tag(&self.root, parsed.epoch, &parsed.ct, &parsed.tag)?;

        // Decapsulate ML-KEM-1024 ciphertext with local private key
        let ml_ss = self
            .bundle
            .decapsulate_mlkem(&parsed.ct)
            .map_err(|_| CoreError::Malformed)?;

        // Advance root key: RootKey_{epoch+1} = HKDF-SHA384(RootKey_{epoch}, Decaps(ct))
        let new_root = Self::hkdf_epoch_root(&self.root, ml_ss.as_slice(), parsed.epoch)?;
        let new_chain = hkdf32(&new_root, DOMAIN_RATCHET_CHAIN, &parsed.epoch.to_be_bytes())?;
        let fresh_bundle = EphemeralKeys::generate().map_err(|_| CoreError::OsRandom)?;

        // Volatile zeroization of old epoch secrets
        self.root.zeroize();
        self.chain.zeroize();
        self.root = new_root;
        self.chain = new_chain;
        self.epoch = parsed.epoch as u64;
        self.bundle = fresh_bundle;
        self.reset_rollover_counters();

        let mut frame_key_bytes = [0u8; 32];
        frame_key_bytes.copy_from_slice(&self.chain);
        Ok(frame_key_bytes)
    }

    /// Autonomous send step using stored peer advertised ML-KEM key.
    pub fn build_in_band_epoch_rekey_auto(
        &mut self,
    ) -> Result<[u8; IN_BAND_REKEY_PAYLOAD_LEN], CoreError> {
        let peer_ek = self
            .peer_bundle
            .as_ref()
            .map(|b| b.ek.clone())
            .ok_or(CoreError::AuthRequired)?;
        self.build_in_band_epoch_rekey(&peer_ek)
    }

    /// Sending step against the peer's advertised `(peer_p_pub, peer_ek)`:
    /// fresh-encaps both halves, evolve root+chain, emit message key plus
    /// fresh step material. Every fallible operation precedes the state commit.
    pub fn send_step(
        &mut self,
        peer_p_pub: &[u8; P384_PK],
        peer_ek: &[u8],
    ) -> Result<(RatchetStep, [u8; 32]), CoreError> {
        if peer_ek.len() != MLKEM_PK {
            return Err(CoreError::Malformed);
        }
        let next_seq = self.send_seq.checked_add(1).ok_or(CoreError::Oversize)?;
        let next_epoch = self.epoch.checked_add(1).ok_or(CoreError::Oversize)?;
        let (ml_ct, hybrid, eph_pub) =
            EphemeralKeys::encapsulate(peer_p_pub, peer_ek).map_err(|_| CoreError::Malformed)?;
        if ml_ct.len() != MLKEM_CT {
            return Err(CoreError::Malformed);
        }
        // Generate the next bundle before mutating the current state. An RNG
        // failure therefore cannot consume the current root/chain or bundle.
        let fresh = EphemeralKeys::generate().map_err(|_| CoreError::OsRandom)?;
        let (new_root, new_chain) = self.evolved(&hybrid)?;
        let msg_key = Self::message_key_for(&new_chain, self.send_seq)?;
        let step = RatchetStep {
            eph_p_pub: eph_pub,
            ml_ct,
            next_p_pub: fresh.p_public,
            next_ek: fresh.ml_ek.clone(),
            epoch: next_epoch,
        };
        self.commit(new_root, new_chain, next_seq, next_epoch, fresh);
        Ok((step, msg_key))
    }

    /// Receiving step: decapsulate the peer's fresh `(eph_p_pub, ml_ct)`
    /// with our current bundle, evolve identically, emit message key,
    /// rotate bundle (consumed — no reuse window).
    pub fn receive_step(
        &mut self,
        peer_eph_p_pub: &[u8; P384_PK],
        peer_ml_ct: &[u8],
    ) -> Result<[u8; 32], CoreError> {
        if peer_ml_ct.len() != MLKEM_CT {
            return Err(CoreError::Malformed);
        }
        let next_seq = self.send_seq.checked_add(1).ok_or(CoreError::Oversize)?;
        let next_epoch = self.epoch.checked_add(1).ok_or(CoreError::Oversize)?;
        let hybrid: Zeroizing<[u8; HYBRID_SS]> = self
            .bundle
            .decapsulate(peer_eph_p_pub, peer_ml_ct)
            .map_err(|_| CoreError::Malformed)?;
        let fresh = EphemeralKeys::generate().map_err(|_| CoreError::OsRandom)?;
        let (new_root, new_chain) = self.evolved(&hybrid)?;
        let msg_key = Self::message_key_for(&new_chain, self.send_seq)?;
        self.commit(new_root, new_chain, next_seq, next_epoch, fresh);
        Ok(msg_key)
    }

    /// Calculate the next root+chain without mutating the current state.
    fn evolved(&self, hybrid: &[u8; HYBRID_SS]) -> Result<([u8; 32], [u8; 32]), CoreError> {
        let epoch_b = self.epoch.to_be_bytes();
        let mut root_info = Vec::with_capacity(DOMAIN_RATCHET_ROOT.len() + 8);
        root_info.extend_from_slice(DOMAIN_RATCHET_ROOT);
        root_info.extend_from_slice(&epoch_b);
        let new_root = hkdf64(&self.root, hybrid, &root_info)?;
        let mut chain_info = Vec::with_capacity(DOMAIN_RATCHET_CHAIN.len() + 8);
        chain_info.extend_from_slice(DOMAIN_RATCHET_CHAIN);
        chain_info.extend_from_slice(&epoch_b);
        let new_chain_full = hkdf64(&self.chain, hybrid, &chain_info)?;
        let mut new_chain = [0u8; 32];
        new_chain.copy_from_slice(&new_chain_full[..32]);
        let mut r32 = [0u8; 32];
        r32.copy_from_slice(&new_root[..32]);
        Ok((r32, new_chain))
    }

    fn commit(
        &mut self,
        new_root: [u8; 32],
        new_chain: [u8; 32],
        next_seq: u64,
        next_epoch: u64,
        fresh: EphemeralKeys,
    ) {
        self.root.zeroize();
        self.chain.zeroize();
        self.root = new_root;
        self.chain = new_chain;
        self.send_seq = next_seq;
        self.epoch = next_epoch;
        self.bundle = fresh;
    }

    /// Message key for a candidate chain and sequence number.
    fn message_key_for(chain: &[u8; 32], seq: u64) -> Result<[u8; 32], CoreError> {
        let seq_b = seq.to_be_bytes();
        let mut info = Vec::with_capacity(3 + 8);
        info.extend_from_slice(b"msg");
        info.extend_from_slice(&seq_b);
        hkdf32(chain, DOMAIN_RATCHET_CHAIN, &info)
    }

    /// Store a skipped message key (bounded; over-budget fails closed).
    pub fn store_skipped(&mut self, key: [u8; 32], seq: u64) -> Result<(), CoreError> {
        if self.skipped.len() >= MAX_SKIPPED_KEYS {
            return Err(CoreError::Oversize);
        }
        self.skipped.push_back((key, seq));
        Ok(())
    }

    /// Take a skipped key by sequence number.
    pub fn take_skipped(&mut self, seq: u64) -> Option<[u8; 32]> {
        let pos = self.skipped.iter().position(|(_, s)| *s == seq)?;
        Some(self.skipped.remove(pos)?.0)
    }
}

fn hkdf32(key: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], CoreError> {
    let hk = Hkdf::<Sha384>::new(Some(salt), key);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| CoreError::Malformed)?;
    Ok(out)
}

fn hkdf64(root: &[u8; 32], pq: &[u8; HYBRID_SS], info: &[u8]) -> Result<[u8; 64], CoreError> {
    let mut ikm = [0u8; 32 + HYBRID_SS];
    ikm[..32].copy_from_slice(root);
    ikm[32..].copy_from_slice(&pq[..]);
    let hk = Hkdf::<Sha384>::new(Some(DOMAIN_RATCHET_ROOT), &ikm);
    let mut out = [0u8; 64];
    hk.expand(info, &mut out)
        .map_err(|_| CoreError::Malformed)?;
    ikm.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_receive_heal_with_fresh_kem() {
        let sk = [0x11u8; 32];
        let mut a = PcsRatchet::new(&sk).unwrap();
        let mut b = PcsRatchet::new(&sk).unwrap();
        // A sends to B using B's advertised bundle; B receives A's fresh CT.
        let (b_x, b_ek) = b.advertise();
        let (step, k_send) = a.send_step(&b_x, &b_ek).unwrap();
        assert_eq!(step.ml_ct.len(), MLKEM_CT);
        assert_eq!(step.next_ek.len(), MLKEM_PK);
        let k_recv = b.receive_step(&step.eph_p_pub, &step.ml_ct).unwrap();
        assert_eq!(k_send, k_recv);
        // Epochs advanced on both sides (healing is per-step).
        assert_eq!(a.epoch(), 1);
        assert_eq!(b.epoch(), 1);
        // Second step uses rotated bundles (no reuse): take fresh adverts.
        let (b_x2, b_ek2) = b.advertise();
        let (step2, k2) = a.send_step(&b_x2, &b_ek2).unwrap();
        let k2r = b.receive_step(&step2.eph_p_pub, &step2.ml_ct).unwrap();
        assert_eq!(k2, k2r);
        assert_ne!(k_send, k2);
    }

    #[test]
    fn counters_fail_closed_at_exhaustion() {
        let sk = [0x33u8; 32];
        let mut a = PcsRatchet::new(&sk).unwrap();
        let mut b = PcsRatchet::new(&sk).unwrap();
        let (b_x, b_ek) = b.advertise();
        a.send_seq = u64::MAX;
        assert!(a.send_step(&b_x, &b_ek).is_err());
        assert_eq!(a.send_seq, u64::MAX);
        assert_eq!(a.epoch, 0);

        a.send_seq = 0;
        let (step, _) = a.send_step(&b_x, &b_ek).unwrap();
        b.epoch = u64::MAX;
        assert!(b.receive_step(&step.eph_p_pub, &step.ml_ct).is_err());
        assert_eq!(b.epoch, u64::MAX);
        assert_eq!(b.send_seq, 0);
    }

    #[test]
    fn malformed_and_bounds_fail_closed() {
        let sk = [0x22u8; 32];
        let mut r = PcsRatchet::new(&sk).unwrap();
        let (x, ek) = r.advertise();
        assert!(r.send_step(&x, &[0u8; 10]).is_err());
        assert!(r.receive_step(&[0u8; P384_PK], &[0u8; 10]).is_err());
        let _ = ek;
        for i in 0..MAX_SKIPPED_KEYS {
            r.store_skipped([0u8; 32], i as u64).unwrap();
        }
        assert_eq!(r.store_skipped([0u8; 32], 9999), Err(CoreError::Oversize));
        assert_eq!(r.take_skipped(7).unwrap(), [0u8; 32]);
        assert!(r.take_skipped(99999).is_none());
    }

    #[test]
    fn wire_serialization_roundtrip_advert_step_confirm() {
        let adv = AdvertBundle {
            p_pub: [0x55u8; P384_PK],
            ek: vec![0x77u8; MLKEM_PK],
            epoch: 42,
        };
        let b = adv.to_bytes();
        assert_eq!(b.len(), ADVERT_WIRE_LEN);
        let decoded_adv = AdvertBundle::from_bytes(&b).unwrap();
        assert_eq!(adv, decoded_adv);

        let step = RatchetStep {
            eph_p_pub: [0x11u8; P384_PK],
            ml_ct: vec![0x22u8; MLKEM_CT],
            next_p_pub: [0x33u8; P384_PK],
            next_ek: vec![0x44u8; MLKEM_PK],
            epoch: 99,
        };
        let step_b = step.to_bytes();
        assert_eq!(step_b.len(), RATCHET_STEP_WIRE_LEN);
        let decoded_step = RatchetStep::from_bytes(&step_b).unwrap();
        assert_eq!(step, decoded_step);

        let msg_adv = RekeyMessage::Advert(adv);
        let wire_adv = msg_adv.to_wire();
        match RekeyMessage::from_wire(&wire_adv).unwrap() {
            RekeyMessage::Advert(a) => assert_eq!(a.epoch, 42),
            _ => panic!("expected Advert"),
        }

        let msg_step = RekeyMessage::Step(step);
        let wire_step = msg_step.to_wire();
        match RekeyMessage::from_wire(&wire_step).unwrap() {
            RekeyMessage::Step(s) => assert_eq!(s.epoch, 99),
            _ => panic!("expected Step"),
        }

        let msg_conf = RekeyMessage::Confirm {
            epoch: 100,
            auth_tag: [0x99u8; 32],
        };
        let wire_conf = msg_conf.to_wire();
        match RekeyMessage::from_wire(&wire_conf).unwrap() {
            RekeyMessage::Confirm { epoch, auth_tag } => {
                assert_eq!(epoch, 100);
                assert_eq!(auth_tag, [0x99u8; 32]);
            }
            _ => panic!("expected Confirm"),
        }
    }

    #[test]
    fn auto_ratchet_with_stored_peer_bundle() {
        let sk = [0x42u8; 32];
        let mut alice = PcsRatchet::new(&sk).unwrap();
        let mut bob = PcsRatchet::new(&sk).unwrap();

        // 1. Bob advertises to Alice
        let bob_adv = bob.advertise_bundle();
        alice.set_peer_bundle(bob_adv);

        // 2. Alice executes auto send_step (encapsulates to Bob's bundle)
        let (step, a_key) = alice.send_step_auto().unwrap();
        assert_eq!(alice.epoch(), 1);

        // 3. Bob receives step with advert (decapsulates and stores Alice's next advert)
        let b_key = bob.receive_step_with_advert(&step).unwrap();
        assert_eq!(bob.epoch(), 1);
        assert_eq!(a_key, b_key);

        // Verify Bob stored Alice's next bundle
        assert!(bob.peer_bundle().is_some());
        assert_eq!(bob.peer_bundle().unwrap().epoch, 1);

        // 4. Bob executes auto send_step back to Alice
        let (step2, b_key2) = bob.send_step_auto().unwrap();
        assert_eq!(bob.epoch(), 2);

        // 5. Alice receives step2
        let a_key2 = alice.receive_step_with_advert(&step2).unwrap();
        assert_eq!(alice.epoch(), 2);
        assert_eq!(a_key2, b_key2);
        assert_ne!(a_key, a_key2);
    }

    #[test]
    fn true_post_compromise_security_epoch_healing_proof() {
        use crate::aead::{open_indexed, seal, DIR_SEND};

        // Shared initial KEX key
        let initial_sk = [0x77u8; 32];
        let mut alice = PcsRatchet::new(&initial_sk).unwrap();
        let mut bob = PcsRatchet::new(&initial_sk).unwrap();

        // Initial state at Epoch 0
        let k0_alice = alice.current_frame_key().unwrap();
        let k0_bob = bob.current_frame_key().unwrap();

        // Normal traffic in Epoch 0
        let frame0 = seal(
            &k0_alice,
            1,
            DIR_SEND,
            crate::frame::FTYPE_MSG,
            b"SECRET_EPOCH_0",
        )
        .unwrap();
        let (_s, _t, pt0) = open_indexed(&k0_bob, DIR_SEND, &frame0).unwrap();
        assert_eq!(&pt0, b"SECRET_EPOCH_0");

        // --- ATTACKER SCENARIO: Compromise of Epoch 0 state ---
        // Attacker steals Alice's Epoch 0 frame key, root, and chain
        let stolen_k0 = k0_alice.clone();
        let stolen_root0 = *alice.root();
        let stolen_chain0 = *alice.chain();

        // Attacker can decrypt Epoch 0 messages (proves compromise model)
        let (_s, _t, pt_stolen) = open_indexed(&stolen_k0, DIR_SEND, &frame0).unwrap();
        assert_eq!(&pt_stolen, b"SECRET_EPOCH_0");

        // --- IN-BAND ASYMMETRIC KEM RATCHET STEP TO EPOCH 1 ---
        // Bob advertises fresh bundle
        let bob_adv = bob.advertise_bundle();
        alice.set_peer_bundle(bob_adv);

        // Alice ratchets to Epoch 1
        let (ratchet_step, a_msg_key) = alice.send_step_auto().unwrap();
        assert_eq!(alice.epoch(), 1);

        // Ciphertext on the wire is intercepted by Attacker
        let wire_step_bytes = ratchet_step.to_bytes();
        let wire_step = RatchetStep::from_bytes(&wire_step_bytes).unwrap();

        // Bob decapsulates fresh KEM and advances to Epoch 1
        let b_msg_key = bob.receive_step_with_advert(&wire_step).unwrap();
        assert_eq!(bob.epoch(), 1);
        assert_eq!(a_msg_key, b_msg_key);

        // Derive active Epoch 1 frame keys
        let k1_alice = crate::aead::FrameKey::from_bytes(a_msg_key);
        let k1_bob = crate::aead::FrameKey::from_bytes(b_msg_key);

        // Alice sends classified tactical message under Epoch 1
        let frame1 = seal(
            &k1_alice,
            2,
            DIR_SEND,
            crate::frame::FTYPE_MSG,
            b"TOP_SECRET_EPOCH_1",
        )
        .unwrap();

        // Bob decrypts successfully under Epoch 1
        let (_s, _t, pt1) = open_indexed(&k1_bob, DIR_SEND, &frame1).unwrap();
        assert_eq!(&pt1, b"TOP_SECRET_EPOCH_1");

        // --- POST-COMPROMISE SECURITY VERIFICATION ---
        // 1. Attacker tries to decrypt Epoch 1 message with stolen Epoch 0 frame key -> FAILS!
        assert!(
            open_indexed(&stolen_k0, DIR_SEND, &frame1).is_err(),
            "Attacker cannot use old key"
        );

        // 2. Attacker tries to evolve their stolen root/chain:
        // Attacker observes wire_step.eph_p_pub and wire_step.ml_ct.
        // But Attacker DOES NOT possess Bob's uncompromised EphemeralKeys private decapsulation key!
        // In ML-KEM-1024 (FIPS 203), decapsulation under the wrong private key produces an IND-CCA2
        // pseudorandom rejection value that completely diverges from the authentic shared secret.
        let bogus_bundle = EphemeralKeys::generate().unwrap();
        let bogus_hybrid = bogus_bundle
            .decapsulate(&wire_step.eph_p_pub, &wire_step.ml_ct)
            .unwrap();
        let mut bogus_ratchet = PcsRatchet::new(&stolen_root0).unwrap();
        bogus_ratchet.chain = stolen_chain0;
        let (_bogus_root, bogus_chain) = bogus_ratchet.evolved(&bogus_hybrid).unwrap();
        let bogus_key = PcsRatchet::message_key_for(&bogus_chain, 0).unwrap();
        let bogus_fk = crate::aead::FrameKey::from_bytes(bogus_key);

        assert!(
            open_indexed(&bogus_fk, DIR_SEND, &frame1).is_err(),
            "Attacker cannot forge or decrypt Epoch 1 frame"
        );
    }
    #[test]
    fn in_band_epoch_rekey_flow_and_post_compromise_security() {
        use crate::aead::{open_indexed, seal, DIR_SEND};

        let initial_sk = [0x5Au8; 32];
        let mut alice = PcsRatchet::new(&initial_sk).unwrap();
        let mut bob = PcsRatchet::new(&initial_sk).unwrap();

        // Bob advertises initial bundle to Alice
        let bob_adv = bob.advertise_bundle();
        alice.set_peer_bundle(bob_adv.clone());

        // Epoch 0 traffic
        let k0_alice = alice.current_frame_key().unwrap();
        let k0_bob = bob.current_frame_key().unwrap();
        let f0 = seal(
            &k0_alice,
            1,
            DIR_SEND,
            crate::frame::FTYPE_MSG,
            b"EPOCH_0_MSG",
        )
        .unwrap();
        let (_s, _t, pt0) = open_indexed(&k0_bob, DIR_SEND, &f0).unwrap();
        assert_eq!(&pt0, b"EPOCH_0_MSG");

        // Attacker dumps RAM of Alice at Epoch 0
        let stolen_root_0 = *alice.root();
        let _stolen_chain_0 = *alice.chain();
        let stolen_k0 = k0_alice.clone();

        // Alice simulates 10,000 transmitted packets (N=10,000 threshold)
        for _ in 0..10_000 {
            alice.note_transmission(64);
        }
        assert!(
            alice.needs_rollover(),
            "must trigger rollover at 10,000 packets"
        );
        let (pkts, bytes) = alice.rollover_counters();
        assert_eq!(pkts, 10_000);
        assert_eq!(bytes, 640_000);

        // Alice triggers in-band continuous epoch rekey (Frame Type 0x07)
        let rekey_payload = alice.build_in_band_epoch_rekey(&bob_adv.ek).unwrap();
        assert_eq!(rekey_payload.len(), IN_BAND_REKEY_PAYLOAD_LEN);
        assert_eq!(alice.epoch(), 1);
        assert!(!alice.needs_rollover(), "counters reset after rollover");
        assert_eq!(alice.rollover_counters(), (0, 0));

        // Attacker intercepts rekey_payload on the wire
        // Bob receives rekey_payload and processes it
        let _new_key_bob = bob.process_in_band_epoch_rekey(&rekey_payload).unwrap();
        assert_eq!(bob.epoch(), 1);
        assert_eq!(bob.rollover_counters(), (0, 0));

        // Alice and Bob derive active Epoch 1 frame keys
        let k1_alice = alice.current_frame_key().unwrap();
        let k1_bob = bob.current_frame_key().unwrap();

        // Alice sends message in Epoch 1
        let f1 = seal(
            &k1_alice,
            2,
            DIR_SEND,
            crate::frame::FTYPE_MSG,
            b"EPOCH_1_SECRET",
        )
        .unwrap();
        let (_s, _t, pt1) = open_indexed(&k1_bob, DIR_SEND, &f1).unwrap();
        assert_eq!(&pt1, b"EPOCH_1_SECRET");

        // --- Post-Compromise Security (PCS) Verification ---
        // 1. Attacker tries to decrypt Epoch 1 message with stolen Epoch 0 frame key -> FAILS!
        assert!(open_indexed(&stolen_k0, DIR_SEND, &f1).is_err());

        // 2. Attacker attempts to compute Epoch 1 root key from stolen Epoch 0 root and wire payload:
        // Attacker parses epoch and ciphertext from wire payload
        let parsed = InBandEpochRekeyPayload::from_bytes(&rekey_payload).unwrap();
        assert_eq!(parsed.epoch, 1);
        // Attacker does NOT have Bob's ML-KEM-1024 private decapsulation key.
        // Trying to decapsulate with an attacker key yields IND-CCA2 rejection value:
        let fake_bundle = EphemeralKeys::generate().unwrap();
        let fake_ml_ss = fake_bundle.decapsulate_mlkem(&parsed.ct).unwrap();
        let fake_root_1 =
            PcsRatchet::hkdf_epoch_root(&stolen_root_0, fake_ml_ss.as_slice(), 1).unwrap();
        let fake_chain_1 = hkdf32(&fake_root_1, DOMAIN_RATCHET_CHAIN, &1u32.to_be_bytes()).unwrap();
        let fake_fk_1 = crate::aead::FrameKey::from_bytes(fake_chain_1);

        // Attacker frame key completely fails to open Epoch 1 ciphertext!
        assert!(
            open_indexed(&fake_fk_1, DIR_SEND, &f1).is_err(),
            "Attacker cannot decrypt Epoch 1"
        );
    }

    #[test]
    fn in_band_epoch_rekey_byte_threshold_and_tamper_defense() {
        let initial_sk = [0x6Bu8; 32];
        let mut alice = PcsRatchet::new(&initial_sk).unwrap();
        let mut bob = PcsRatchet::new(&initial_sk).unwrap();

        let bob_adv = bob.advertise_bundle();

        // Configure 1 MB byte threshold for testing
        alice.set_rollover_thresholds(50_000, 1024 * 1024);
        assert!(!alice.needs_rollover());

        // Send 1.2 MB data
        alice.note_transmission(1_200_000);
        assert!(
            alice.needs_rollover(),
            "must trigger rollover when byte threshold reached"
        );

        let rekey_payload = alice.build_in_band_epoch_rekey(&bob_adv.ek).unwrap();

        // 1. Tampered AuthTag fails closed
        let mut tampered_payload = rekey_payload;
        tampered_payload[IN_BAND_REKEY_PAYLOAD_LEN - 1] ^= 0x01; // flip last tag byte
        assert_eq!(
            bob.process_in_band_epoch_rekey(&tampered_payload),
            Err(CoreError::BadSignature)
        );
        assert_eq!(
            bob.epoch(),
            0,
            "Bob state must not advance on bad signature"
        );

        // 2. Tampered ciphertext fails closed (AuthTag check catches tampering)
        let mut tampered_ct = rekey_payload;
        tampered_ct[10] ^= 0x01;
        assert_eq!(
            bob.process_in_band_epoch_rekey(&tampered_ct),
            Err(CoreError::BadSignature)
        );
        assert_eq!(bob.epoch(), 0);

        // 3. Stale / out-of-order epoch index fails closed
        let mut stale_payload = rekey_payload;
        stale_payload[..4].copy_from_slice(&999u32.to_be_bytes());
        assert_eq!(
            bob.process_in_band_epoch_rekey(&stale_payload),
            Err(CoreError::Stale)
        );

        // 4. Authentic rekey succeeds
        assert!(bob.process_in_band_epoch_rekey(&rekey_payload).is_ok());
        assert_eq!(bob.epoch(), 1);
    }
}
