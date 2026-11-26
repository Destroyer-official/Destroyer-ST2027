//! Anonymous Membership & Clearance Attestation (`bLSAG` on Ristretto255)
//!
//! CRITICAL CRYPTOGRAPHIC DISCLOSURE (NO HALLUCINATION / FAIL-CLOSED):
//! The prior `PQZKP1` SHA3 Merkle construction exposed `leaf_hash` unblinded in
//! `blinded_leaf_hash` and never verified `proof_response` or `nullifier` derivation.
//! Because verifying hidden preimages of an unstructured SHA3 Merkle tree requires an
//! audited external SNARK/STARK/MPC-in-the-Head prover, this module replaces `PQZKP1`
//! with a mathematically sound **Ristretto255 Linkable Spontaneous Anonymous Group
//! (`bLSAG`)** signature over the tier-committed ring of cleared identities.
//!
//! - Security guarantees: Cryptographic signer anonymity within the tier ring,
//!   cross-epoch DDH unlinkability (`I = x * H_p(epoch)`), unforgeability, and
//!   mathematically enforced epoch nullifier binding (`I` verified in ring loop).
//! - Quantum posture: Classical 128-bit discrete-log security (Ristretto255).
//!   NOT post-quantum secure against a future CRQC; `IS_POST_QUANTUM == false` and
//!   `verify_strict_pq()` unconditionally refuses (`CoreError::ClassicalOnlyRefused`)
//!   until a vetted hash-based STARK/MPCitH prover crate is integrated.

use std::collections::HashSet;

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use sha2::{Digest as Sha2Digest, Sha512};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::policy::CoreError;

pub const CLEARANCE_UNCLASSIFIED: u8 = 1;
pub const CLEARANCE_CONFIDENTIAL: u8 = 2;
pub const CLEARANCE_SECRET: u8 = 3;
pub const CLEARANCE_TOP_SECRET: u8 = 4;
pub const CLEARANCE_TOP_SECRET_SCI_NC3: u8 = 5;

pub const MERKLE_DEPTH: usize = 8; // 256 slots for legacy accumulator helper
pub const MAX_RING_MEMBERS: usize = 256;
pub const NUM_TIERS: usize = 5;
pub const RING_WIRE_MAGIC: &[u8; 6] = b"PQZKP2";

const DOMAIN_LEAF: &[u8] = b"STRATCOM-ID-LEAF-V1:";
const DOMAIN_MERKLE_NODE: &[u8] = b"STRATCOM-MERKLE-NODE-V1:";
const DOMAIN_RING_SK: &[u8] = b"STRATCOM-RING-SK-V2:";
const DOMAIN_TIER_RING: &[u8] = b"STRATCOM-TIER-RING-V2:";
const DOMAIN_RING_ROOT: &[u8] = b"STRATCOM-RING-ROOT-V2:";
const DOMAIN_HASH_POINT: &[u8] = b"STRATCOM-BLSAG-HP-V2:";
const DOMAIN_RING_MSG: &[u8] = b"STRATCOM-BLSAG-MSG-V2:";
const DOMAIN_RING_CHAL: &[u8] = b"STRATCOM-BLSAG-CHAL-V2:";

/// Computes internal Merkle node hash: H(DOMAIN || left || right)
pub fn hash_merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(DOMAIN_MERKLE_NODE);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn random_nonzero_scalar() -> Result<Scalar, CoreError> {
    for _ in 0..16 {
        let mut wide = [0u8; 64];
        getrandom::fill(&mut wide).map_err(|_| CoreError::OsRandom)?;
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        if s != Scalar::ZERO {
            return Ok(s);
        }
    }
    Err(CoreError::OsRandom)
}

fn hash_to_ristretto(domain: &[u8], data: &[u8]) -> Result<RistrettoPoint, CoreError> {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(data);
    let mut uniform = [0u8; 64];
    uniform.copy_from_slice(&hasher.finalize());
    let pt = RistrettoPoint::from_uniform_bytes(&uniform);
    if pt.is_identity() {
        return Err(CoreError::Malformed);
    }
    Ok(pt)
}

fn ring_challenge_scalar(
    msg_hash: &[u8; 32],
    l_pt: &RistrettoPoint,
    r_pt: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_RING_CHAL);
    hasher.update(msg_hash);
    hasher.update(l_pt.compress().as_bytes());
    hasher.update(r_pt.compress().as_bytes());
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn compute_tier_digest(tier: u8, ring_pks: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(DOMAIN_TIER_RING);
    hasher.update([tier]);
    hasher.update((ring_pks.len() as u16).to_be_bytes());
    for pk in ring_pks {
        hasher.update(pk);
    }
    hasher.finalize().into()
}

fn compute_ring_root(tier_digests: &[[u8; 32]; NUM_TIERS]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(DOMAIN_RING_ROOT);
    for td in tier_digests {
        hasher.update(td);
    }
    hasher.finalize().into()
}

fn compute_attestation_message(
    root: &[u8; 32],
    claimed_min_clearance: u8,
    epoch_id: &[u8; 16],
    session_nonce: &[u8; 32],
    tier_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(DOMAIN_RING_MSG);
    hasher.update(root);
    hasher.update([claimed_min_clearance]);
    hasher.update(epoch_id);
    hasher.update(session_nonce);
    hasher.update(tier_digest);
    hasher.finalize().into()
}

/// Tactical Node Secret Identity Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TacticalIdentityRecord {
    pub callsign: String,
    pub serial_number: String,
    pub clearance_level: u8,
    pub public_key_fingerprint: [u8; 32],
}

impl TacticalIdentityRecord {
    /// Computes canonical leaf commitment hash (legacy/compatibility API).
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(DOMAIN_LEAF);
        hasher.update((self.callsign.len() as u16).to_be_bytes());
        hasher.update(self.callsign.as_bytes());
        hasher.update((self.serial_number.len() as u16).to_be_bytes());
        hasher.update(self.serial_number.as_bytes());
        hasher.update([self.clearance_level]);
        hasher.update(self.public_key_fingerprint);
        hasher.finalize().into()
    }

    fn derive_ring_secret(&self) -> Result<Scalar, CoreError> {
        if !(CLEARANCE_UNCLASSIFIED..=CLEARANCE_TOP_SECRET_SCI_NC3).contains(&self.clearance_level) {
            return Err(CoreError::Malformed);
        }
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_RING_SK);
        hasher.update((self.callsign.len() as u16).to_be_bytes());
        hasher.update(self.callsign.as_bytes());
        hasher.update((self.serial_number.len() as u16).to_be_bytes());
        hasher.update(self.serial_number.as_bytes());
        hasher.update([self.clearance_level]);
        hasher.update(self.public_key_fingerprint);
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hasher.finalize());
        let sk = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        if sk == Scalar::ZERO {
            return Err(CoreError::Malformed);
        }
        Ok(sk)
    }

    /// Public Ristretto255 identity point enrolled in clearance rings.
    pub fn ring_public_key(&self) -> Result<[u8; 32], CoreError> {
        let mut sk = self.derive_ring_secret()?;
        let pk = RistrettoPoint::mul_base(&sk).compress().to_bytes();
        sk.zeroize();
        Ok(pk)
    }
}

/// Legacy Merkle Tree Accumulator kept only for direct `compute_leaf_hash` /
/// `build_merkle_accumulator` test compatibility; operational attestation uses `RingAccumulator`.
#[derive(Debug, Clone)]
pub struct MerkleAccumulator {
    pub leaves: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

impl MerkleAccumulator {
    pub fn build(leaf_hashes: Vec<[u8; 32]>) -> Self {
        let num_leaves = 1 << MERKLE_DEPTH;
        let mut padded = leaf_hashes;
        padded.resize(num_leaves, [0u8; 32]);

        let mut current_level = padded.clone();
        for _ in 0..MERKLE_DEPTH {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            let (chunks, _) = current_level.as_chunks::<2>();
            for chunk in chunks {
                next_level.push(hash_merkle_node(&chunk[0], &chunk[1]));
            }
            current_level = next_level;
        }

        Self {
            leaves: padded,
            root: current_level[0],
        }
    }

    pub fn open_path(&self, leaf_index: usize) -> Result<(Vec<[u8; 32]>, u32), CoreError> {
        if leaf_index >= self.leaves.len() {
            return Err(CoreError::Malformed);
        }

        let mut path = Vec::with_capacity(MERKLE_DEPTH);
        let mut current_level = self.leaves.clone();
        let mut idx = leaf_index;

        for _ in 0..MERKLE_DEPTH {
            let sibling_idx = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
            path.push(current_level[sibling_idx]);

            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            let (chunks, _) = current_level.as_chunks::<2>();
            for chunk in chunks {
                next_level.push(hash_merkle_node(&chunk[0], &chunk[1]));
            }
            current_level = next_level;
            idx /= 2;
        }

        Ok((path, leaf_index as u32))
    }
}

/// Tiered Ristretto255 Clearance Accumulator.
#[derive(Debug, Clone)]
pub struct RingAccumulator {
    pub tier_rings: [Vec<[u8; 32]>; NUM_TIERS],
    pub tier_digests: [[u8; 32]; NUM_TIERS],
    pub root: [u8; 32],
}

impl RingAccumulator {
    pub fn build(records: &[TacticalIdentityRecord]) -> Result<Self, CoreError> {
        if records.is_empty() || records.len() > MAX_RING_MEMBERS {
            return Err(CoreError::Malformed);
        }
        let mut tier_rings: [Vec<[u8; 32]>; NUM_TIERS] = Default::default();
        let mut seen_all = HashSet::with_capacity(records.len());

        for rec in records {
            if !(CLEARANCE_UNCLASSIFIED..=CLEARANCE_TOP_SECRET_SCI_NC3).contains(&rec.clearance_level) {
                return Err(CoreError::Malformed);
            }
            let pk = rec.ring_public_key()?;
            if !seen_all.insert(pk) {
                return Err(CoreError::Malformed);
            }
            for t in 1..=rec.clearance_level {
                tier_rings[(t - 1) as usize].push(pk);
            }
        }

        let mut tier_digests = [[0u8; 32]; NUM_TIERS];
        for (i, ring) in tier_rings.iter_mut().enumerate() {
            ring.sort_unstable();
            tier_digests[i] = compute_tier_digest((i + 1) as u8, ring);
        }
        let root = compute_ring_root(&tier_digests);
        Ok(Self {
            tier_rings,
            tier_digests,
            root,
        })
    }
}

/// Sound Anonymous Clearance Proof (`bLSAG` on Ristretto255, non-PQ classical DL security).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqZkpIdentityProof {
    pub root: [u8; 32],
    pub claimed_min_clearance: u8,
    pub epoch_id: [u8; 16],
    pub session_nonce: [u8; 32],
    pub nullifier: [u8; 32],
    pub tier_digests: [[u8; 32]; NUM_TIERS],
    pub ring_pks: Vec<[u8; 32]>,
    pub c0: [u8; 32],
    pub responses: Vec<[u8; 32]>,
}

impl PqZkpIdentityProof {
    /// Honest cryptographic disclosure: Ristretto255 bLSAG is classical DL, NOT post-quantum.
    pub const IS_POST_QUANTUM: bool = false;

    pub const fn is_post_quantum() -> bool {
        Self::IS_POST_QUANTUM
    }

    pub fn prove_ring(
        identity: &TacticalIdentityRecord,
        accumulator: &RingAccumulator,
        claimed_min_clearance: u8,
        epoch_id: &[u8; 16],
        session_nonce: &[u8; 32],
    ) -> Result<Self, CoreError> {
        if !(CLEARANCE_UNCLASSIFIED..=CLEARANCE_TOP_SECRET_SCI_NC3).contains(&claimed_min_clearance) {
            return Err(CoreError::Malformed);
        }
        if identity.clearance_level < claimed_min_clearance {
            return Err(CoreError::AuthRequired);
        }

        let tier_idx = (claimed_min_clearance - 1) as usize;
        let ring_pks = &accumulator.tier_rings[tier_idx];
        if ring_pks.is_empty() || ring_pks.len() > MAX_RING_MEMBERS {
            return Err(CoreError::Malformed);
        }

        let my_pk = identity.ring_public_key()?;
        let signer_idx = ring_pks
            .iter()
            .position(|pk| bool::from(pk.ct_eq(&my_pk)))
            .ok_or(CoreError::BadSignature)?;

        let n = ring_pks.len();
        let mut points = Vec::with_capacity(n);
        for pk_bytes in ring_pks {
            let pt = CompressedRistretto::from_slice(pk_bytes)
                .map_err(|_| CoreError::Malformed)?
                .decompress()
                .ok_or(CoreError::Malformed)?;
            if pt.is_identity() {
                return Err(CoreError::Malformed);
            }
            points.push(pt);
        }

        let mut sk = identity.derive_ring_secret()?;
        let h_ep = hash_to_ristretto(DOMAIN_HASH_POINT, epoch_id)?;
        let key_image = h_ep * sk;
        if key_image.is_identity() {
            sk.zeroize();
            return Err(CoreError::Malformed);
        }
        let nullifier = key_image.compress().to_bytes();

        let msg_hash = compute_attestation_message(
            &accumulator.root,
            claimed_min_clearance,
            epoch_id,
            session_nonce,
            &accumulator.tier_digests[tier_idx],
        );

        let mut alpha = random_nonzero_scalar()?;
        let l_start = RistrettoPoint::mul_base(&alpha);
        let r_start = h_ep * alpha;

        let mut challenges = vec![Scalar::ZERO; n];
        let mut responses_scalar = vec![Scalar::ZERO; n];

        let mut curr = (signer_idx + 1) % n;
        challenges[curr] = ring_challenge_scalar(&msg_hash, &l_start, &r_start);

        for _ in 0..(n - 1) {
            let s_j = random_nonzero_scalar()?;
            let l_j = RistrettoPoint::mul_base(&s_j) + points[curr] * challenges[curr];
            let r_j = h_ep * s_j + key_image * challenges[curr];
            responses_scalar[curr] = s_j;
            let next = (curr + 1) % n;
            challenges[next] = ring_challenge_scalar(&msg_hash, &l_j, &r_j);
            curr = next;
        }

        // Close the ring at signer_idx: s_idx = alpha - c_idx * sk
        responses_scalar[signer_idx] = alpha - challenges[signer_idx] * sk;
        alpha.zeroize();
        sk.zeroize();

        let c0 = challenges[0].to_bytes();
        let responses = responses_scalar.iter().map(|s| s.to_bytes()).collect();
        for r in &mut responses_scalar {
            r.zeroize();
        }

        Ok(Self {
            root: accumulator.root,
            claimed_min_clearance,
            epoch_id: *epoch_id,
            session_nonce: *session_nonce,
            nullifier,
            tier_digests: accumulator.tier_digests,
            ring_pks: ring_pks.clone(),
            c0,
            responses,
        })
    }

    /// Fail-closed gate when a post-quantum zero-knowledge proof is strictly required.
    pub fn verify_strict_pq(
        &self,
        _trusted_accumulator_root: &[u8; 32],
        _expected_session_nonce: &[u8; 32],
        _expected_min_clearance: u8,
        _epoch_cache: &mut Vec<[u8; 32]>,
    ) -> Result<u8, CoreError> {
        Err(CoreError::ClassicalOnlyRefused)
    }

    /// Verifies the ring signature, tier commitment to `trusted_accumulator_root`,
    /// clearance threshold, session nonce, and epoch nullifier in constant time.
    pub fn verify(
        &self,
        trusted_accumulator_root: &[u8; 32],
        expected_session_nonce: &[u8; 32],
        expected_min_clearance: u8,
        epoch_cache: &mut Vec<[u8; 32]>,
    ) -> Result<u8, CoreError> {
        if !(CLEARANCE_UNCLASSIFIED..=CLEARANCE_TOP_SECRET_SCI_NC3).contains(&self.claimed_min_clearance)
            || !(CLEARANCE_UNCLASSIFIED..=CLEARANCE_TOP_SECRET_SCI_NC3).contains(&expected_min_clearance)
        {
            return Err(CoreError::Malformed);
        }

        if !bool::from(self.root.ct_eq(trusted_accumulator_root)) {
            return Err(CoreError::KeyMismatch);
        }

        if !bool::from(self.session_nonce.ct_eq(expected_session_nonce)) {
            return Err(CoreError::NonceMismatch);
        }

        if self.claimed_min_clearance < expected_min_clearance {
            return Err(CoreError::AuthRequired);
        }

        for seen in epoch_cache.iter() {
            if bool::from(seen.ct_eq(&self.nullifier)) {
                return Err(CoreError::Stale);
            }
        }

        if self.ring_pks.is_empty()
            || self.ring_pks.len() > MAX_RING_MEMBERS
            || self.responses.len() != self.ring_pks.len()
        {
            return Err(CoreError::Malformed);
        }

        // Verify the presented ring set is the exact tier committed in trusted_accumulator_root
        let tier_idx = (self.claimed_min_clearance - 1) as usize;
        let expected_tier_digest = compute_tier_digest(self.claimed_min_clearance, &self.ring_pks);
        if !bool::from(expected_tier_digest.ct_eq(&self.tier_digests[tier_idx])) {
            return Err(CoreError::BadSignature);
        }
        let recomputed_root = compute_ring_root(&self.tier_digests);
        if !bool::from(recomputed_root.ct_eq(trusted_accumulator_root)) {
            return Err(CoreError::KeyMismatch);
        }

        // Parse & validate distinct canonical Ristretto public keys and non-identity key image
        let mut seen_pks = HashSet::with_capacity(self.ring_pks.len());
        let mut points = Vec::with_capacity(self.ring_pks.len());
        for pk_bytes in &self.ring_pks {
            if !seen_pks.insert(*pk_bytes) {
                return Err(CoreError::Malformed);
            }
            let pt = CompressedRistretto::from_slice(pk_bytes)
                .map_err(|_| CoreError::Malformed)?
                .decompress()
                .ok_or(CoreError::Malformed)?;
            if pt.is_identity() {
                return Err(CoreError::Malformed);
            }
            points.push(pt);
        }

        let key_image = CompressedRistretto::from_slice(&self.nullifier)
            .map_err(|_| CoreError::Malformed)?
            .decompress()
            .ok_or(CoreError::BadSignature)?;
        if key_image.is_identity() {
            return Err(CoreError::BadSignature);
        }

        let h_ep = hash_to_ristretto(DOMAIN_HASH_POINT, &self.epoch_id)?;
        let msg_hash = compute_attestation_message(
            trusted_accumulator_root,
            self.claimed_min_clearance,
            &self.epoch_id,
            expected_session_nonce,
            &self.tier_digests[tier_idx],
        );

        let mut c = Option::<Scalar>::from(Scalar::from_canonical_bytes(self.c0))
            .ok_or(CoreError::Malformed)?;

        for (i, pt) in points.iter().enumerate() {
            let s_i = Option::<Scalar>::from(Scalar::from_canonical_bytes(self.responses[i]))
                .ok_or(CoreError::Malformed)?;
            let l_i = RistrettoPoint::mul_base(&s_i) + (*pt) * c;
            let r_i = h_ep * s_i + key_image * c;
            c = ring_challenge_scalar(&msg_hash, &l_i, &r_i);
        }

        if !bool::from(c.to_bytes().ct_eq(&self.c0)) {
            return Err(CoreError::BadSignature);
        }

        epoch_cache.push(self.nullifier);
        Ok(self.claimed_min_clearance)
    }

    /// Serializes proof to canonical PQZKP2 wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(352 + self.ring_pks.len() * 64);
        out.extend_from_slice(RING_WIRE_MAGIC);
        out.extend_from_slice(&self.root);
        out.push(self.claimed_min_clearance);
        out.extend_from_slice(&self.epoch_id);
        out.extend_from_slice(&self.session_nonce);
        out.extend_from_slice(&self.nullifier);
        for td in &self.tier_digests {
            out.extend_from_slice(td);
        }
        out.extend_from_slice(&(self.ring_pks.len() as u16).to_be_bytes());
        for pk in &self.ring_pks {
            out.extend_from_slice(pk);
        }
        out.extend_from_slice(&self.c0);
        for resp in &self.responses {
            out.extend_from_slice(resp);
        }
        out
    }

    /// Deserializes PQZKP2 wire bytes. Legacy `PQZKP1` is strictly refused.
    pub fn from_bytes(wire: &[u8]) -> Result<Self, CoreError> {
        // Minimum header: 6 + 32 + 1 + 16 + 32 + 32 + 160 + 2 + 32 (1 pk) + 32 (c0) + 32 (1 resp) = 377B
        if wire.len() < 377 || &wire[..6] != RING_WIRE_MAGIC {
            return Err(CoreError::Malformed);
        }
        let mut offset = 6;

        let mut root = [0u8; 32];
        root.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let claimed_min_clearance = wire[offset];
        offset += 1;

        let mut epoch_id = [0u8; 16];
        epoch_id.copy_from_slice(&wire[offset..offset + 16]);
        offset += 16;

        let mut session_nonce = [0u8; 32];
        session_nonce.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let mut tier_digests = [[0u8; 32]; NUM_TIERS];
        for td in &mut tier_digests {
            td.copy_from_slice(&wire[offset..offset + 32]);
            offset += 32;
        }

        let ring_len = u16::from_be_bytes(
            wire[offset..offset + 2]
                .try_into()
                .map_err(|_| CoreError::Malformed)?,
        ) as usize;
        offset += 2;

        if ring_len == 0 || ring_len > MAX_RING_MEMBERS {
            return Err(CoreError::Malformed);
        }

        let expected_rem = ring_len * 32 + 32 + ring_len * 32;
        if wire.len() != offset + expected_rem {
            return Err(CoreError::Malformed);
        }

        let mut ring_pks = Vec::with_capacity(ring_len);
        for _ in 0..ring_len {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&wire[offset..offset + 32]);
            offset += 32;
            ring_pks.push(pk);
        }

        let mut c0 = [0u8; 32];
        c0.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let mut responses = Vec::with_capacity(ring_len);
        for _ in 0..ring_len {
            let mut r = [0u8; 32];
            r.copy_from_slice(&wire[offset..offset + 32]);
            offset += 32;
            responses.push(r);
        }

        Ok(Self {
            root,
            claimed_min_clearance,
            epoch_id,
            session_nonce,
            nullifier,
            tier_digests,
            ring_pks,
            c0,
            responses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_records() -> (TacticalIdentityRecord, TacticalIdentityRecord, TacticalIdentityRecord) {
        let sub = TacticalIdentityRecord {
            callsign: "TITAN-SSBN-773".to_string(),
            serial_number: "USN-STRAT-9912".to_string(),
            clearance_level: CLEARANCE_TOP_SECRET_SCI_NC3,
            public_key_fingerprint: [0x42u8; 32],
        };
        let silo = TacticalIdentityRecord {
            callsign: "MINUTEMAN-SILO-08".to_string(),
            serial_number: "USAF-NC3-4410".to_string(),
            clearance_level: CLEARANCE_TOP_SECRET,
            public_key_fingerprint: [0x55u8; 32],
        };
        let uav = TacticalIdentityRecord {
            callsign: "REAPER-UAV-14".to_string(),
            serial_number: "USAF-UAV-8812".to_string(),
            clearance_level: CLEARANCE_SECRET,
            public_key_fingerprint: [0x66u8; 32],
        };
        (sub, silo, uav)
    }

    #[test]
    fn test_blsag_ring_roundtrip_and_replay_rejection() {
        let (sub, silo, uav) = sample_records();
        let acc = RingAccumulator::build(&[sub.clone(), silo, uav]).unwrap();
        let epoch = [0xEEu8; 16];
        let nonce = [0xAAu8; 32];

        let proof = PqZkpIdentityProof::prove_ring(&sub, &acc, CLEARANCE_SECRET, &epoch, &nonce).unwrap();
        // Leaf hash must never leak on the wire
        let leaf = sub.leaf_hash();
        let wire = proof.to_bytes();
        assert!(!wire.windows(32).any(|w| w == leaf));

        let mut cache = Vec::new();
        let lvl = proof.verify(&acc.root, &nonce, CLEARANCE_SECRET, &mut cache).unwrap();
        assert_eq!(lvl, CLEARANCE_SECRET);

        // Same key image nullifier within epoch fails closed
        assert_eq!(
            proof.verify(&acc.root, &nonce, CLEARANCE_SECRET, &mut cache),
            Err(CoreError::Stale)
        );
    }

    #[test]
    fn test_tampered_response_nullifier_and_pqzkp1_rejected() {
        let (sub, silo, uav) = sample_records();
        let acc = RingAccumulator::build(&[sub.clone(), silo, uav]).unwrap();
        let epoch = [0x11u8; 16];
        let nonce = [0x22u8; 32];
        let proof = PqZkpIdentityProof::prove_ring(&sub, &acc, CLEARANCE_SECRET, &epoch, &nonce).unwrap();

        // 1. Corrupting ANY response scalar must fail verification
        let mut bad_resp = proof.clone();
        bad_resp.responses[0][0] ^= 0x01;
        // Flip high bits cleanly to ensure distinct scalar (mod l)
        bad_resp.responses[1][1] ^= 0x80;
        let mut cache = Vec::new();
        assert!(bad_resp.verify(&acc.root, &nonce, CLEARANCE_SECRET, &mut cache).is_err());

        // 2. Spoofing nullifier breaks ring verification (prevents Sybil bypass)
        let mut spoofed_null = proof.clone();
        spoofed_null.nullifier = RistrettoPoint::mul_base(&Scalar::from(9u64)).compress().to_bytes();
        assert_eq!(
            spoofed_null.verify(&acc.root, &nonce, CLEARANCE_SECRET, &mut cache),
            Err(CoreError::BadSignature)
        );

        // 3. Legacy PQZKP1 header rejected fail-closed
        let mut legacy = proof.to_bytes();
        legacy[..6].copy_from_slice(b"PQZKP1");
        assert_eq!(PqZkpIdentityProof::from_bytes(&legacy), Err(CoreError::Malformed));
    }

    #[test]
    fn test_strict_pq_refuses_classical_blsag_and_insufficient_clearance_denied() {
        let (sub, silo, _) = sample_records();
        let patrol = TacticalIdentityRecord {
            callsign: "COAST-GUARD-PATROL-11".to_string(),
            serial_number: "USCG-991".to_string(),
            clearance_level: CLEARANCE_CONFIDENTIAL,
            public_key_fingerprint: [0x11u8; 32],
        };
        let acc = RingAccumulator::build(&[sub, silo, patrol.clone()]).unwrap();
        let epoch = [0x01u8; 16];
        let nonce = [0x02u8; 32];

        assert_eq!(
            PqZkpIdentityProof::prove_ring(&patrol, &acc, CLEARANCE_TOP_SECRET, &epoch, &nonce),
            Err(CoreError::AuthRequired)
        );

        let proof = PqZkpIdentityProof::prove_ring(&patrol, &acc, CLEARANCE_CONFIDENTIAL, &epoch, &nonce).unwrap();
        let mut cache = Vec::new();
        assert!(!PqZkpIdentityProof::is_post_quantum());
        assert_eq!(
            proof.verify_strict_pq(&acc.root, &nonce, CLEARANCE_CONFIDENTIAL, &mut cache),
            Err(CoreError::ClassicalOnlyRefused)
        );
    }
}
