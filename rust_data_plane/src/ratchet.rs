//! Project-specific fresh-KEM ratchet inspired by SPQR/Triple Ratchet.
//!
//! This is not an implementation of Signal SPQR or the Triple Ratchet
//! specification, and no equivalent security or interoperability is claimed.
//! Reference behavior mirrors `double_ratchet.py` v2 semantics and
//! `secure_transmit_2027.py::rehandshake`, but WITHOUT any legacy mode:
//! there is no v1 KEM-reuse path in this crate, so "downgrade to reuse"
//! is unrepresentable. Every DH step performs a FRESH hybrid encapsulation
//! (fresh ML-KEM-1024 + fresh ephemeral X25519 against the peer's
//! advertised bundle); any fresh-KEM failure is a hard error (strict abort
//! is the only behavior — no flag exists to disable it).
//!
//! Construction (per step, role-separated epochs):
//! ```text
//! (ml_ct, pq_hybrid, eph_x) = encaps(peer_x_pub, peer_ek)  // fresh both halves
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

use crate::kem::{EphemeralKeys, HYBRID_SS, MLKEM_CT, MLKEM_PK};
use crate::policy::{CoreError, DOMAIN_RATCHET_CHAIN, DOMAIN_RATCHET_ROOT, MAX_SKIPPED_KEYS};

/// One sending step's fresh material for the peer.
pub struct RatchetStep {
    /// Our fresh ephemeral X25519 public (32 bytes).
    pub eph_x_pub: [u8; 32],
    /// Fresh ML-KEM ciphertext (1568 bytes) for this step.
    pub ml_ct: Vec<u8>,
    /// Our NEXT advertised bundle for the following step.
    pub next_x_pub: [u8; 32],
    /// Next encapsulation key bytes (1568).
    pub next_ek: Vec<u8>,
    /// Epoch number (monotonic).
    pub epoch: u64,
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
    /// Skipped message keys (bounded).
    skipped: VecDeque<([u8; 32], u64)>,
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
            skipped: VecDeque::new(),
        })
    }

    /// Currently advertised `(x_pub, ek)` pair.
    pub fn advertise(&self) -> ([u8; 32], Vec<u8>) {
        (self.bundle.x_public, self.bundle.ml_ek.clone())
    }

    /// Epoch (monotonic step counter).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Sending step against the peer's advertised `(peer_x_pub, peer_ek)`:
    /// fresh-encaps both halves, evolve root+chain, emit message key plus
    /// fresh step material. Every fallible operation precedes the state commit.
    pub fn send_step(
        &mut self,
        peer_x_pub: &[u8; 32],
        peer_ek: &[u8],
    ) -> Result<(RatchetStep, [u8; 32]), CoreError> {
        if peer_ek.len() != MLKEM_PK {
            return Err(CoreError::Malformed);
        }
        let next_seq = self.send_seq.checked_add(1).ok_or(CoreError::Oversize)?;
        let next_epoch = self.epoch.checked_add(1).ok_or(CoreError::Oversize)?;
        let (ml_ct, hybrid, eph_pub) =
            EphemeralKeys::encapsulate(peer_x_pub, peer_ek).map_err(|_| CoreError::Malformed)?;
        if ml_ct.len() != MLKEM_CT {
            return Err(CoreError::Malformed);
        }
        // Generate the next bundle before mutating the current state. An RNG
        // failure therefore cannot consume the current root/chain or bundle.
        let fresh = EphemeralKeys::generate().map_err(|_| CoreError::OsRandom)?;
        let (new_root, new_chain) = self.evolved(&hybrid)?;
        let msg_key = Self::message_key_for(&new_chain, self.send_seq)?;
        let step = RatchetStep {
            eph_x_pub: eph_pub,
            ml_ct,
            next_x_pub: fresh.x_public,
            next_ek: fresh.ml_ek.clone(),
            epoch: next_epoch,
        };
        self.commit(new_root, new_chain, next_seq, next_epoch, fresh);
        Ok((step, msg_key))
    }

    /// Receiving step: decapsulate the peer's fresh `(eph_x_pub, ml_ct)`
    /// with our current bundle, evolve identically, emit message key,
    /// rotate bundle (consumed — no reuse window).
    pub fn receive_step(
        &mut self,
        peer_eph_x_pub: &[u8; 32],
        peer_ml_ct: &[u8],
    ) -> Result<[u8; 32], CoreError> {
        if peer_ml_ct.len() != MLKEM_CT {
            return Err(CoreError::Malformed);
        }
        let next_seq = self.send_seq.checked_add(1).ok_or(CoreError::Oversize)?;
        let next_epoch = self.epoch.checked_add(1).ok_or(CoreError::Oversize)?;
        let hybrid: Zeroizing<[u8; HYBRID_SS]> = self
            .bundle
            .decapsulate(peer_eph_x_pub, peer_ml_ct)
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
    let mut ikm = [0u8; 96];
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
        let k_recv = b.receive_step(&step.eph_x_pub, &step.ml_ct).unwrap();
        assert_eq!(k_send, k_recv);
        // Epochs advanced on both sides (healing is per-step).
        assert_eq!(a.epoch(), 1);
        assert_eq!(b.epoch(), 1);
        // Second step uses rotated bundles (no reuse): take fresh adverts.
        let (b_x2, b_ek2) = b.advertise();
        let (step2, k2) = a.send_step(&b_x2, &b_ek2).unwrap();
        let k2r = b.receive_step(&step2.eph_x_pub, &step2.ml_ct).unwrap();
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
        assert!(b.receive_step(&step.eph_x_pub, &step.ml_ct).is_err());
        assert_eq!(b.epoch, u64::MAX);
        assert_eq!(b.send_seq, 0);
    }

    #[test]
    fn malformed_and_bounds_fail_closed() {
        let sk = [0x22u8; 32];
        let mut r = PcsRatchet::new(&sk).unwrap();
        let (x, ek) = r.advertise();
        assert!(r.send_step(&x, &[0u8; 10]).is_err());
        assert!(r.receive_step(&[0u8; 32], &[0u8; 10]).is_err());
        let _ = ek;
        for i in 0..MAX_SKIPPED_KEYS {
            r.store_skipped([0u8; 32], i as u64).unwrap();
        }
        assert_eq!(r.store_skipped([0u8; 32], 9999), Err(CoreError::Oversize));
        assert_eq!(r.take_skipped(7).unwrap(), [0u8; 32]);
        assert!(r.take_skipped(99999).is_none());
    }
}
