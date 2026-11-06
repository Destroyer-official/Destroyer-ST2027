//! Zero-Gap Defense-in-Depth Unified Message Pipeline.
//!
//! Chains independent post-quantum cryptographic layers fail-closed:
//!   - Pre-flight: NSA RTB dirty-word spillage scan + NC3 safety gate detection
//!   - Layer 1 (Inner): Post-Quantum Double Ratchet (fresh ML-KEM-1024 + P-384)
//!   - Layer 2 (Outer): Native AEAD framing (AES-256-GCM + decoupled anti-replay)
//!   - Metadata resistance: Fixed-quanta padding with CSPRNG whitening (256/512/1024/2048/4096/8192/16384 bytes)
//!   - Continuous Epoch Ratchet (CER): Epoch key rotation via HKDF-SHA512 every 128 messages

use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{self, FrameKey, DIR_RECV, DIR_SEND};
use crate::nc3::check_nc3_safety_gate;
use crate::policy::CoreError;
use crate::ratchet::PcsRatchet;
use crate::replay::AntiReplayWindow;
use crate::zero_trust::{inspect_content_rtb, ClearanceLevel};

pub const PIPELINE_MAGIC: &[u8; 2] = b"ZG";
pub const PIPELINE_VERSION: &[u8; 7] = b"ZGDP-V1";

pub const PIPELINE_TYPE_MSG: u8 = 0x01;
pub const PIPELINE_TYPE_FILE: u8 = 0x02;
pub const PIPELINE_TYPE_NC3: u8 = 0x03;

pub const CER_EPOCH_INTERVAL: u64 = 128;
pub const LAYER2_HKDF_SALT: &[u8] = b"destroyer-p2p-rust-v1";
pub const LAYER2_HKDF_INFO: &[u8] = b"destroyer/frame/v1";
pub const CER_HKDF_SALT: &[u8] = b"destroyer-cer-epoch-v1";
pub const WAR_KEY_HKDF_SALT: &[u8] = b"destroyer-nc3-war-key-salt";

pub const PAD_QUANTA: [usize; 7] = [256, 512, 1024, 2048, 4096, 8192, 16384];

/// Derive a 32-byte frame key from a shared hybrid secret using HKDF-SHA512.
pub fn derive_frame_key_sha512(hybrid_root_key: &[u8; 32]) -> Result<[u8; 32], CoreError> {
    let hk = Hkdf::<Sha512>::new(Some(LAYER2_HKDF_SALT), hybrid_root_key);
    let mut out = [0u8; 32];
    hk.expand(LAYER2_HKDF_INFO, &mut out)
        .map_err(|_| CoreError::Malformed)?;
    Ok(out)
}

/// Derive a 32-byte military NC3 DEFCON-1 war-key from master keying material.
pub fn derive_war_key_sha512(master_secret: &[u8], info: &[u8]) -> Result<[u8; 32], CoreError> {
    let hk = Hkdf::<Sha512>::new(Some(WAR_KEY_HKDF_SALT), master_secret);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| CoreError::Malformed)?;
    Ok(out)
}

/// Pad data to the next quantum boundary with CSPRNG whitening.
/// Length prefix: 4 bytes BE original length.
pub fn quantize_pad(data: &[u8]) -> Result<Vec<u8>, CoreError> {
    let original_len = data.len();
    let total_unpadded = 4 + original_len;

    let q_max = PAD_QUANTA[PAD_QUANTA.len() - 1];
    let padded_len = if total_unpadded > q_max {
        total_unpadded.div_ceil(q_max) * q_max
    } else {
        let mut target = q_max;
        for &q in &PAD_QUANTA {
            if total_unpadded <= q {
                target = q;
                break;
            }
        }
        target
    };

    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(&(original_len as u32).to_be_bytes());
    out.extend_from_slice(data);

    let pad_needed = padded_len - total_unpadded;
    if pad_needed > 0 {
        let mut pad_bytes = vec![0u8; pad_needed];
        getrandom::fill(&mut pad_bytes).map_err(|_| CoreError::OsRandom)?;
        out.extend_from_slice(&pad_bytes);
        pad_bytes.zeroize();
    }

    Ok(out)
}

/// Strip quantized padding, recovering original payload.
pub fn quantize_unpad(padded: &[u8]) -> Result<Vec<u8>, CoreError> {
    if padded.len() < 4 {
        return Err(CoreError::Malformed);
    }
    let len_b: [u8; 4] = padded[0..4].try_into().map_err(|_| CoreError::Malformed)?;
    let original_len = u32::from_be_bytes(len_b) as usize;

    if 4 + original_len > padded.len() {
        return Err(CoreError::Malformed);
    }

    Ok(padded[4..4 + original_len].to_vec())
}

/// Header wrapper: MAGIC(2) + VERSION(7) + TYPE(1) + LEN(4) + payload
pub fn wrap_header(msg_type: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 7 + 1 + 4 + data.len());
    out.extend_from_slice(PIPELINE_MAGIC);
    out.extend_from_slice(PIPELINE_VERSION);
    out.push(msg_type);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Unwrap header: returns (msg_type, data)
pub fn unwrap_header(frame: &[u8]) -> Result<(u8, Vec<u8>), CoreError> {
    const HEADER_LEN: usize = 2 + 7 + 1 + 4;
    if frame.len() < HEADER_LEN {
        return Err(CoreError::Malformed);
    }
    if &frame[0..2] != PIPELINE_MAGIC || &frame[2..9] != PIPELINE_VERSION {
        return Err(CoreError::Malformed);
    }

    let msg_type = frame[9];
    let len_b: [u8; 4] = frame[10..14].try_into().map_err(|_| CoreError::Malformed)?;
    let data_len = u32::from_be_bytes(len_b) as usize;

    if frame.len() < HEADER_LEN + data_len {
        return Err(CoreError::Malformed);
    }

    Ok((msg_type, frame[HEADER_LEN..HEADER_LEN + data_len].to_vec()))
}

/// Unified Zero-Gap Pipeline state orchestrator.
pub struct ZeroGapPipeline {
    frame_key: Option<FrameKey>,
    epoch_root: Zeroizing<[u8; 32]>,
    send_seq: u64,
    replay: AntiReplayWindow,
    is_initiator: bool,
    seal_count: u64,
    current_epoch: u64,
    stealth_mode: bool,
}

impl Drop for ZeroGapPipeline {
    fn drop(&mut self) {
        self.frame_key = None;
        self.epoch_root.zeroize();
    }
}

impl ZeroGapPipeline {
    /// Initialize a new Zero-Gap multi-layer defense pipeline.
    pub fn new(
        hybrid_root_key: &[u8; 32],
        is_initiator: bool,
        stealth_mode: bool,
    ) -> Result<Self, CoreError> {
        let fk_bytes = derive_frame_key_sha512(hybrid_root_key)?;
        let frame_key = FrameKey::from_bytes(fk_bytes);

        let mut epoch_root = [0u8; 32];
        epoch_root.copy_from_slice(hybrid_root_key);

        Ok(Self {
            frame_key: Some(frame_key),
            epoch_root: Zeroizing::new(epoch_root),
            send_seq: 1,
            replay: AntiReplayWindow::new(),
            is_initiator,
            seal_count: 0,
            current_epoch: 0,
            stealth_mode,
        })
    }

    fn send_dir(&self) -> u8 {
        if self.is_initiator {
            DIR_SEND
        } else {
            DIR_RECV
        }
    }

    fn recv_dir(&self) -> u8 {
        if self.is_initiator {
            DIR_RECV
        } else {
            DIR_SEND
        }
    }

    /// Rotate Continuous Epoch Ratchet (CER) for post-compromise security healing.
    pub fn rotate_epoch(&mut self) -> Result<u64, CoreError> {
        self.current_epoch = self
            .current_epoch
            .checked_add(1)
            .ok_or(CoreError::Oversize)?;
        let epoch_info = (self.current_epoch as u32).to_be_bytes();

        let hk = Hkdf::<Sha512>::new(Some(CER_HKDF_SALT), &self.epoch_root[..]);
        let mut next_root = [0u8; 32];
        hk.expand(&epoch_info, &mut next_root)
            .map_err(|_| CoreError::Malformed)?;

        let next_fk = derive_frame_key_sha512(&next_root)?;
        self.frame_key = Some(FrameKey::from_bytes(next_fk));
        self.epoch_root = Zeroizing::new(next_root);
        next_root.zeroize();

        Ok(self.current_epoch)
    }

    /// Rotate Continuous Epoch Ratchet (CER) with fresh post-quantum KEM encapsulation (True PCS).
    pub fn rotate_epoch_asymmetric(
        &mut self,
        ratchet: &mut PcsRatchet,
        peer_p_pub: &[u8; crate::kem::P384_PK],
        peer_ek: &[u8],
    ) -> Result<(crate::ratchet::RatchetStep, u64), CoreError> {
        let (step, msg_key) = ratchet.send_step(peer_p_pub, peer_ek)?;
        self.current_epoch = self
            .current_epoch
            .checked_add(1)
            .ok_or(CoreError::Oversize)?;
        let next_fk = derive_frame_key_sha512(&msg_key)?;
        self.frame_key = Some(FrameKey::from_bytes(next_fk));
        self.epoch_root = Zeroizing::new(msg_key);
        Ok((step, self.current_epoch))
    }

    /// Process peer's asymmetric ratchet step to advance epoch with True PCS.
    pub fn receive_epoch_asymmetric(
        &mut self,
        ratchet: &mut PcsRatchet,
        peer_eph_p_pub: &[u8; crate::kem::P384_PK],
        peer_ml_ct: &[u8],
    ) -> Result<u64, CoreError> {
        let msg_key = ratchet.receive_step(peer_eph_p_pub, peer_ml_ct)?;
        self.current_epoch = self
            .current_epoch
            .checked_add(1)
            .ok_or(CoreError::Oversize)?;
        let next_fk = derive_frame_key_sha512(&msg_key)?;
        self.frame_key = Some(FrameKey::from_bytes(next_fk));
        self.epoch_root = Zeroizing::new(msg_key);
        Ok(self.current_epoch)
    }

    /// Seal a message through all defense layers:
    /// Pre-flight -> Stealth Header Wrap -> Quantize Pad -> Ratchet Seal -> AEAD Frame
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        msg_type: u8,
        clearance: ClearanceLevel,
        ratchet: &mut PcsRatchet,
        peer_p_pub: &[u8; crate::kem::P384_PK],
        peer_ek: &[u8],
    ) -> Result<(crate::ratchet::RatchetStep, Vec<u8>), CoreError> {
        if plaintext.is_empty() {
            return Err(CoreError::Malformed);
        }

        // ── Pre-flight 1: RTB classified indicator scan ──────────────────
        if let Err(_indicator) = inspect_content_rtb(plaintext) {
            if clearance != ClearanceLevel::TopSecret {
                return Err(CoreError::ZeroTrustViolation);
            }
        }

        // ── Pre-flight 2: NC3 safety gate keyword scan ───────────────────
        if msg_type == PIPELINE_TYPE_MSG && check_nc3_safety_gate(plaintext).is_err() {
            // Single-officer routine message contains nuclear directives! Block fail-closed.
            return Err(CoreError::ZeroTrustViolation);
        }

        // ── Inner Framing & Quantization ─────────────────────────────────
        let payload_to_protect = if self.stealth_mode {
            wrap_header(msg_type, plaintext)
        } else {
            plaintext.to_vec()
        };

        let padded = quantize_pad(&payload_to_protect)?;

        // ── Layer 1: Post-Quantum Ratchet step ───────────────────────────
        let (step, msg_key) = ratchet.send_step(peer_p_pub, peer_ek)?;
        let inner_key = FrameKey::from_bytes(msg_key);

        // Seal with inner ratchet message key
        let inner_sealed = aead::seal_with_len(
            &inner_key,
            0,
            DIR_SEND,
            crate::frame::FTYPE_MSG,
            padded.len() as u16,
            &padded,
        )
        .map_err(|_| CoreError::Malformed)?;

        // ── Layer 2: Outer Native AEAD Carrier ───────────────────────────
        let fk = self.frame_key.as_ref().ok_or(CoreError::AuthRequired)?;
        let seq = self.send_seq;
        self.send_seq = self.send_seq.checked_add(1).ok_or(CoreError::Oversize)?;

        let outer_sealed = aead::seal_with_len(
            fk,
            seq,
            self.send_dir(),
            crate::frame::FTYPE_MSG,
            inner_sealed.len() as u16,
            &inner_sealed,
        )
        .map_err(|_| CoreError::Malformed)?;

        let final_frame = if self.stealth_mode {
            outer_sealed
        } else {
            wrap_header(msg_type, &outer_sealed)
        };

        self.seal_count += 1;
        if self.seal_count.is_multiple_of(CER_EPOCH_INTERVAL) {
            let _ = self.rotate_epoch();
        }

        Ok((step, final_frame))
    }

    /// Open a message through all defense layers (reverse order):
    /// Outer AEAD Check & Open -> Replay Mark -> Inner Ratchet Open -> Unpad -> Unwrap Header
    pub fn open(
        &mut self,
        frame: &[u8],
        ratchet: &mut PcsRatchet,
        peer_eph_p_pub: &[u8; crate::kem::P384_PK],
        peer_ml_ct: &[u8],
    ) -> Result<(u8, Vec<u8>), CoreError> {
        if frame.is_empty() {
            return Err(CoreError::Malformed);
        }

        // ── Step 1: Unwrap outer header if non-stealth ───────────────────
        let (outer_msg_type, sealed_body) =
            if !self.stealth_mode && frame.starts_with(PIPELINE_MAGIC) {
                unwrap_header(frame)?
            } else {
                (PIPELINE_TYPE_MSG, frame.to_vec())
            };

        // ── Step 2: Layer 2 Outer AEAD Strip with Anti-Replay Gate ───────
        let mut fk = self.frame_key.clone().ok_or(CoreError::AuthRequired)?;

        // Peek with current frame key; if that fails or seq is in a future epoch, attempt epoch synchronization
        let mut peeked = aead::peek_seq(&fk, &sealed_body);
        if peeked.is_none()
            || peeked
                .map(|s| s > 0 && (s - 1) / CER_EPOCH_INTERVAL > self.current_epoch)
                .unwrap_or(false)
        {
            let mut trial_epoch = self.current_epoch;
            let mut trial_root = *self.epoch_root;
            for _ in 0..8 {
                trial_epoch += 1;
                let epoch_info = (trial_epoch as u32).to_be_bytes();
                let hk = Hkdf::<Sha512>::new(Some(CER_HKDF_SALT), &trial_root[..]);
                let mut next_root = [0u8; 32];
                if hk.expand(&epoch_info, &mut next_root).is_ok() {
                    if let Ok(next_fk_bytes) = derive_frame_key_sha512(&next_root) {
                        let candidate_fk = FrameKey::from_bytes(next_fk_bytes);
                        if let Some(s) = aead::peek_seq(&candidate_fk, &sealed_body) {
                            if s > 0 && (s - 1) / CER_EPOCH_INTERVAL == trial_epoch {
                                self.current_epoch = trial_epoch;
                                self.epoch_root = Zeroizing::new(next_root);
                                self.frame_key = Some(candidate_fk.clone());
                                fk = candidate_fk;
                                peeked = Some(s);
                                break;
                            }
                        }
                    }
                    trial_root = next_root;
                }
            }
        }

        let peeked = peeked.ok_or(CoreError::Malformed)?;
        if !self.replay.check(peeked) {
            self.replay.note_drop();
            return Err(CoreError::Malformed);
        }

        let (seq, _ftype, inner_sealed) = aead::open_indexed(&fk, self.recv_dir(), &sealed_body)
            .map_err(|_| CoreError::Malformed)?;

        if seq != peeked {
            self.replay.note_drop();
            return Err(CoreError::Malformed);
        }

        // Authentication verified! Mutate replay window
        self.replay.mark(seq);

        // ── Step 3: Layer 1 Inner Ratchet Open ───────────────────────────
        let recv_msg_key = ratchet.receive_step(peer_eph_p_pub, peer_ml_ct)?;
        let inner_key = FrameKey::from_bytes(recv_msg_key);

        let (_in_seq, _in_ftype, padded_raw) =
            aead::open_indexed(&inner_key, DIR_SEND, &inner_sealed)
                .map_err(|_| CoreError::Malformed)?;

        // ── Step 4: Quantized unpad ──────────────────────────────────────
        let unpadded = quantize_unpad(&padded_raw)?;

        self.seal_count += 1;
        if self.seal_count.is_multiple_of(CER_EPOCH_INTERVAL) {
            let _ = self.rotate_epoch();
        }

        // ── Step 5: Inner Header Unwrap ──────────────────────────────────
        if self.stealth_mode {
            unwrap_header(&unpadded)
        } else {
            Ok((outer_msg_type, unpadded))
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn seal_count(&self) -> u64 {
        self.seal_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantize_pad_and_unpad_roundtrip() {
        let data = b"Classified military tactical datagram payload";
        let padded = quantize_pad(data).expect("pad");
        assert_eq!(padded.len(), 256); // Fits in smallest 256 quantum

        let unpadded = quantize_unpad(&padded).expect("unpad");
        assert_eq!(unpadded, data);
    }

    #[test]
    fn header_wrap_unwrap_roundtrip() {
        let msg = b"FLASH_OVERRIDE_DIRECTIVE";
        let wrapped = wrap_header(PIPELINE_TYPE_NC3, msg);
        let (mtype, data) = unwrap_header(&wrapped).expect("unwrap");
        assert_eq!(mtype, PIPELINE_TYPE_NC3);
        assert_eq!(data, msg);
    }

    #[test]
    fn war_key_and_frame_key_derivation_deterministic() {
        let root = [0x5Au8; 32];
        let fk1 = derive_frame_key_sha512(&root).unwrap();
        let fk2 = derive_frame_key_sha512(&root).unwrap();
        assert_eq!(fk1, fk2);

        let wk1 = derive_war_key_sha512(&root, b"NORAD_STRATCOM_DEFCON1").unwrap();
        let wk2 = derive_war_key_sha512(&root, b"NORAD_STRATCOM_DEFCON1").unwrap();
        assert_eq!(wk1, wk2);
        assert_ne!(fk1, wk1);
    }

    #[test]
    fn pipeline_full_seal_and_open_roundtrip() {
        let root = [0x77u8; 32];
        let mut p_send = ZeroGapPipeline::new(&root, true, true).expect("init send");
        let mut p_recv = ZeroGapPipeline::new(&root, false, true).expect("init recv");

        let mut r_send = PcsRatchet::new(&root).expect("ratchet send");
        let mut r_recv = PcsRatchet::new(&root).expect("ratchet recv");

        let (b_x, b_ek) = r_recv.advertise();

        let msg = b"AUTHENTICATED TACTICAL COORDINATES";
        let (step, wire_frame) = p_send
            .seal(
                msg,
                PIPELINE_TYPE_MSG,
                ClearanceLevel::TopSecret,
                &mut r_send,
                &b_x,
                &b_ek,
            )
            .expect("seal");

        let (mtype, opened) = p_recv
            .open(&wire_frame, &mut r_recv, &step.eph_p_pub, &step.ml_ct)
            .expect("open");

        assert_eq!(mtype, PIPELINE_TYPE_MSG);
        assert_eq!(opened, msg);
    }

    #[test]
    fn safety_gate_blocks_nuclear_keywords_in_chat() {
        let root = [0x88u8; 32];
        let mut p = ZeroGapPipeline::new(&root, true, true).unwrap();
        let mut r = PcsRatchet::new(&root).unwrap();
        let (x, ek) = r.advertise();

        let dirty = b"Please verify PAL code for the ICBM";
        let res = p.seal(
            dirty,
            PIPELINE_TYPE_MSG,
            ClearanceLevel::TopSecret,
            &mut r,
            &x,
            &ek,
        );
        assert_eq!(res.unwrap_err(), CoreError::ZeroTrustViolation);
    }

    #[test]
    fn pipeline_asymmetric_epoch_rekey_pcs() {
        let root = [0x99u8; 32];
        let mut p_send = ZeroGapPipeline::new(&root, true, true).expect("init send");
        let mut p_recv = ZeroGapPipeline::new(&root, false, true).expect("init recv");

        let mut r_send = PcsRatchet::new(&root).expect("ratchet send");
        let mut r_recv = PcsRatchet::new(&root).expect("ratchet recv");

        let (b_x, b_ek) = r_recv.advertise();

        // 1. Asymmetric rekey from send -> recv
        let (step, new_epoch_send) = p_send
            .rotate_epoch_asymmetric(&mut r_send, &b_x, &b_ek)
            .unwrap();
        let new_epoch_recv = p_recv
            .receive_epoch_asymmetric(&mut r_recv, &step.eph_p_pub, &step.ml_ct)
            .unwrap();

        assert_eq!(new_epoch_send, 1);
        assert_eq!(new_epoch_recv, 1);
        assert_eq!(p_send.current_epoch(), 1);
        assert_eq!(p_recv.current_epoch(), 1);

        // 2. Next message seals and opens under Epoch 1
        let (b_x2, b_ek2) = r_recv.advertise();
        let (step2, wire_frame) = p_send
            .seal(
                b"EPOCH_1_TACTICAL_COMMAND",
                PIPELINE_TYPE_MSG,
                ClearanceLevel::TopSecret,
                &mut r_send,
                &b_x2,
                &b_ek2,
            )
            .unwrap();

        let (mtype, opened) = p_recv
            .open(&wire_frame, &mut r_recv, &step2.eph_p_pub, &step2.ml_ct)
            .unwrap();

        assert_eq!(mtype, PIPELINE_TYPE_MSG);
        assert_eq!(opened, b"EPOCH_1_TACTICAL_COMMAND");
    }

    #[test]
    fn pipeline_auto_epoch_rotation_and_sync() {
        let root = [0xAAu8; 32];
        let mut p_send = ZeroGapPipeline::new(&root, true, true).expect("init send");
        let mut p_recv = ZeroGapPipeline::new(&root, false, true).expect("init recv");

        let mut r_send = PcsRatchet::new(&root).expect("ratchet send");
        let mut r_recv = PcsRatchet::new(&root).expect("ratchet recv");

        // Send 130 messages across the 128 CER_EPOCH_INTERVAL threshold
        for i in 1..=130 {
            let (b_x, b_ek) = r_recv.advertise();
            let payload = format!("TACTICAL_PAYLOAD_{}", i);
            let (step, wire_frame) = p_send
                .seal(
                    payload.as_bytes(),
                    PIPELINE_TYPE_MSG,
                    ClearanceLevel::TopSecret,
                    &mut r_send,
                    &b_x,
                    &b_ek,
                )
                .expect("seal");

            let (mtype, opened) = p_recv
                .open(&wire_frame, &mut r_recv, &step.eph_p_pub, &step.ml_ct)
                .expect("open");

            assert_eq!(mtype, PIPELINE_TYPE_MSG);
            assert_eq!(opened, payload.as_bytes());
        }

        assert_eq!(p_send.current_epoch(), 1);
        assert_eq!(p_recv.current_epoch(), 1);
    }
}
