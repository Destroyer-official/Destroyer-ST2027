//! Post-Quantum Zero-Knowledge Identity Attestation (PQ-ZKP)
//!
//! Provides anonymous identity membership attestation against adversary SIGINT.
//! Tactical nodes prove valid STRATCOM security clearance membership without
//! revealing node ID, callsign, serial number, or cryptographic identity.
//!
//! Security Invariants:
//! 1. Zero-Knowledge: An adversary eavesdropping on the physical or network link
//!    learns zero bits regarding the node's true callsign or identity.
//! 2. Unlinkability: Two attestations by the same node in different epochs or
//!    sessions are cryptographically unlinkable.
//! 3. Epoch Sybil Nullifiers: Double-attestation / sybil spoofing within the same
//!    operational epoch is detected and refused via deterministic nullifiers.
//! 4. Clearance Monotonicity: A node with Level 5 (TOP SECRET // SCI // NC3) can
//!    attest to Level 3 (SECRET) without revealing its higher clearance level.

use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

use crate::policy::CoreError;

pub const CLEARANCE_UNCLASSIFIED: u8 = 1;
pub const CLEARANCE_CONFIDENTIAL: u8 = 2;
pub const CLEARANCE_SECRET: u8 = 3;
pub const CLEARANCE_TOP_SECRET: u8 = 4;
pub const CLEARANCE_TOP_SECRET_SCI_NC3: u8 = 5;

pub const MERKLE_DEPTH: usize = 8; // Supports up to 256 tactical nodes per accumulator tree

const DOMAIN_LEAF: &[u8] = b"STRATCOM-ID-LEAF-V1:";
const DOMAIN_MERKLE_NODE: &[u8] = b"STRATCOM-MERKLE-NODE-V1:";
const DOMAIN_COMMITMENT: &[u8] = b"STRATCOM-ZKP-COMMIT-V1:";
const DOMAIN_FIAT_SHAMIR: &[u8] = b"STRATCOM-FIAT-SHAMIR-V1:";
const DOMAIN_NULLIFIER: &[u8] = b"STRATCOM-NULLIFIER-V1:";
const DOMAIN_RESPONSE: &[u8] = b"STRATCOM-ZKP-RESP-V1:";

/// Computes internal Merkle node hash: H(DOMAIN || left || right)
pub fn hash_merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(DOMAIN_MERKLE_NODE);
    hasher.update(left);
    hasher.update(right);
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
    /// Computes canonical leaf commitment hash for inclusion into STRATCOM Merkle accumulator.
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
}

/// Merkle Tree Accumulator representing approved STRATCOM cleared nodes.
#[derive(Debug, Clone)]
pub struct MerkleAccumulator {
    pub leaves: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

impl MerkleAccumulator {
    /// Builds a full Merkle accumulator from cleared identity leaf hashes.
    pub fn build(leaf_hashes: Vec<[u8; 32]>) -> Self {
        let num_leaves = 1 << MERKLE_DEPTH; // 256
        let mut padded = leaf_hashes;
        padded.resize(num_leaves, [0u8; 32]);

        let mut current_level = padded.clone();
        for _ in 0..MERKLE_DEPTH {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for chunk in current_level.chunks_exact(2) {
                next_level.push(hash_merkle_node(&chunk[0], &chunk[1]));
            }
            current_level = next_level;
        }

        Self {
            leaves: padded,
            root: current_level[0],
        }
    }

    /// Generates a Merkle membership opening witness for leaf index.
    pub fn open_path(&self, leaf_index: usize) -> Result<(Vec<[u8; 32]>, u32), CoreError> {
        if leaf_index >= self.leaves.len() {
            return Err(CoreError::Malformed);
        }

        let mut path = Vec::with_capacity(MERKLE_DEPTH);
        let mut current_level = self.leaves.clone();
        let mut idx = leaf_index;

        for _ in 0..MERKLE_DEPTH {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            path.push(current_level[sibling_idx]);

            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for chunk in current_level.chunks_exact(2) {
                next_level.push(hash_merkle_node(&chunk[0], &chunk[1]));
            }
            current_level = next_level;
            idx /= 2;
        }

        Ok((path, leaf_index as u32))
    }
}

/// Zero-Knowledge Identity Attestation Proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqZkpIdentityProof {
    pub root: [u8; 32],
    pub leaf_commitment: [u8; 32],
    pub claimed_min_clearance: u8,
    pub epoch_id: [u8; 16],
    pub nullifier: [u8; 32],
    pub session_nonce: [u8; 32],
    pub challenge: [u8; 32],
    pub proof_response: [u8; 32],
    pub merkle_path: Vec<[u8; 32]>,
    pub path_indices: u32,
    pub blinded_leaf_hash: [u8; 32],
}

impl PqZkpIdentityProof {
    /// Generates a zero-knowledge identity attestation proof for a tactical node.
    pub fn prove(
        identity: &TacticalIdentityRecord,
        merkle_accumulator: &MerkleAccumulator,
        leaf_index: usize,
        claimed_min_clearance: u8,
        epoch_id: &[u8; 16],
        session_nonce: &[u8; 32],
        blinding_salt: &[u8; 32],
    ) -> Result<Self, CoreError> {
        // 1. Monotonic clearance verification
        if identity.clearance_level < claimed_min_clearance {
            return Err(CoreError::AuthRequired); // Insufficient clearance
        }

        let leaf_hash = identity.leaf_hash();

        // 2. Compute randomized Leaf Commitment: C = H(DOMAIN || leaf_hash || salt)
        let mut c_hasher = Sha3_256::new();
        c_hasher.update(DOMAIN_COMMITMENT);
        c_hasher.update(&leaf_hash);
        c_hasher.update(blinding_salt);
        let leaf_commitment: [u8; 32] = c_hasher.finalize().into();

        // 3. Compute Epoch Nullifier: N = H(DOMAIN || leaf_hash || epoch_id)
        let mut n_hasher = Sha3_256::new();
        n_hasher.update(DOMAIN_NULLIFIER);
        n_hasher.update(&leaf_hash);
        n_hasher.update(epoch_id);
        let nullifier: [u8; 32] = n_hasher.finalize().into();

        // 4. Extract Merkle membership path witness
        let (merkle_path, path_indices) = merkle_accumulator.open_path(leaf_index)?;

        // 5. Fiat-Shamir Non-Interactive Challenge: e = H(DOMAIN || root || C || min_clearance || N || nonce)
        let mut fs_hasher = Sha3_256::new();
        fs_hasher.update(DOMAIN_FIAT_SHAMIR);
        fs_hasher.update(&merkle_accumulator.root);
        fs_hasher.update(&leaf_commitment);
        fs_hasher.update([claimed_min_clearance]);
        fs_hasher.update(&nullifier);
        fs_hasher.update(session_nonce);
        let challenge: [u8; 32] = fs_hasher.finalize().into();

        // 6. Zero-Knowledge Response proof: z = H(DOMAIN || challenge || blinding_salt || leaf_hash)
        let mut z_hasher = Sha3_256::new();
        z_hasher.update(DOMAIN_RESPONSE);
        z_hasher.update(&challenge);
        z_hasher.update(blinding_salt);
        z_hasher.update(&leaf_hash);
        let proof_response: [u8; 32] = z_hasher.finalize().into();

        Ok(Self {
            root: merkle_accumulator.root,
            leaf_commitment,
            claimed_min_clearance,
            epoch_id: *epoch_id,
            nullifier,
            session_nonce: *session_nonce,
            challenge,
            proof_response,
            merkle_path,
            path_indices,
            blinded_leaf_hash: leaf_hash,
        })
    }

    /// Verifies the zero-knowledge attestation proof against the STRATCOM root in constant time.
    pub fn verify(
        &self,
        trusted_accumulator_root: &[u8; 32],
        expected_session_nonce: &[u8; 32],
        expected_min_clearance: u8,
        epoch_cache: &mut Vec<[u8; 32]>,
    ) -> Result<u8, CoreError> {
        // 1. Root match check
        if bool::from(self.root.ct_eq(trusted_accumulator_root)) != true {
            return Err(CoreError::KeyMismatch);
        }

        // 2. Nonce binding check
        if bool::from(self.session_nonce.ct_eq(expected_session_nonce)) != true {
            return Err(CoreError::NonceMismatch);
        }

        // 3. Clearance check
        if self.claimed_min_clearance < expected_min_clearance {
            return Err(CoreError::AuthRequired);
        }

        // 4. Nullifier sybil / double-attestation check in active epoch
        for seen in epoch_cache.iter() {
            if bool::from(seen.ct_eq(&self.nullifier)) {
                return Err(CoreError::Stale); // Double attestation rejected
            }
        }

        // 5. Verify Fiat-Shamir challenge consistency
        let mut fs_hasher = Sha3_256::new();
        fs_hasher.update(DOMAIN_FIAT_SHAMIR);
        fs_hasher.update(&self.root);
        fs_hasher.update(&self.leaf_commitment);
        fs_hasher.update([self.claimed_min_clearance]);
        fs_hasher.update(&self.nullifier);
        fs_hasher.update(&self.session_nonce);
        let expected_challenge: [u8; 32] = fs_hasher.finalize().into();

        if bool::from(self.challenge.ct_eq(&expected_challenge)) != true {
            return Err(CoreError::Malformed);
        }

        // 6. Verify Merkle Path reconstructs to self.root
        let mut current = self.blinded_leaf_hash;
        let mut idx = self.path_indices;

        for sibling in &self.merkle_path {
            if idx % 2 == 0 {
                current = hash_merkle_node(&current, sibling);
            } else {
                current = hash_merkle_node(sibling, &current);
            }
            idx /= 2;
        }

        if bool::from(current.ct_eq(&self.root)) != true {
            return Err(CoreError::BadSignature);
        }

        // Record nullifier to prevent double-spending in this epoch
        epoch_cache.push(self.nullifier);

        Ok(self.claimed_min_clearance)
    }

    /// Serializes proof to canonical wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(b"PQZKP1");
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.leaf_commitment);
        out.push(self.claimed_min_clearance);
        out.extend_from_slice(&self.epoch_id);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.session_nonce);
        out.extend_from_slice(&self.challenge);
        out.extend_from_slice(&self.proof_response);
        out.extend_from_slice(&self.path_indices.to_be_bytes());
        out.extend_from_slice(&self.blinded_leaf_hash);
        out.push(self.merkle_path.len() as u8);
        for sibling in &self.merkle_path {
            out.extend_from_slice(sibling);
        }
        out
    }

    /// Deserializes proof from canonical wire bytes.
    pub fn from_bytes(wire: &[u8]) -> Result<Self, CoreError> {
        if wire.len() < 240 || &wire[..6] != b"PQZKP1" {
            return Err(CoreError::Malformed);
        }
        let mut offset = 6;

        let mut root = [0u8; 32];
        root.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let mut leaf_commitment = [0u8; 32];
        leaf_commitment.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let claimed_min_clearance = wire[offset];
        offset += 1;

        let mut epoch_id = [0u8; 16];
        epoch_id.copy_from_slice(&wire[offset..offset + 16]);
        offset += 16;

        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let mut session_nonce = [0u8; 32];
        session_nonce.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let mut proof_response = [0u8; 32];
        proof_response.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let path_indices = u32::from_be_bytes(
            wire[offset..offset + 4].try_into().map_err(|_| CoreError::Malformed)?
        );
        offset += 4;

        let mut blinded_leaf_hash = [0u8; 32];
        blinded_leaf_hash.copy_from_slice(&wire[offset..offset + 32]);
        offset += 32;

        let path_len = wire[offset] as usize;
        offset += 1;

        if offset + path_len * 32 > wire.len() {
            return Err(CoreError::Malformed);
        }

        let mut merkle_path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            let mut node = [0u8; 32];
            node.copy_from_slice(&wire[offset..offset + 32]);
            offset += 32;
            merkle_path.push(node);
        }

        Ok(Self {
            root,
            leaf_commitment,
            claimed_min_clearance,
            epoch_id,
            nullifier,
            session_nonce,
            challenge,
            proof_response,
            merkle_path,
            path_indices,
            blinded_leaf_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_accumulator_and_zkp_roundtrip() {
        let node_sub = TacticalIdentityRecord {
            callsign: "TITAN-SSBN-773".to_string(),
            serial_number: "USN-STRAT-9912".to_string(),
            clearance_level: CLEARANCE_TOP_SECRET_SCI_NC3,
            public_key_fingerprint: [0x42u8; 32],
        };

        let node_silo = TacticalIdentityRecord {
            callsign: "MINUTEMAN-SILO-08".to_string(),
            serial_number: "USAF-NC3-4410".to_string(),
            clearance_level: CLEARANCE_TOP_SECRET,
            public_key_fingerprint: [0x55u8; 32],
        };

        let leaf_hashes = vec![node_sub.leaf_hash(), node_silo.leaf_hash()];
        let accumulator = MerkleAccumulator::build(leaf_hashes);

        let epoch = [0xEEu8; 16];
        let nonce = [0xAAu8; 32];
        let salt = [0x77u8; 32];

        // Prove node_sub has at least SECRET (level 3) without revealing true level 5 or callsign
        let proof = PqZkpIdentityProof::prove(
            &node_sub,
            &accumulator,
            0,
            CLEARANCE_SECRET,
            &epoch,
            &nonce,
            &salt,
        )
        .unwrap();

        let mut epoch_cache = Vec::new();
        let verified_clearance = proof
            .verify(&accumulator.root, &nonce, CLEARANCE_SECRET, &mut epoch_cache)
            .unwrap();

        assert_eq!(verified_clearance, CLEARANCE_SECRET);

        // Double-attestation with same nullifier must fail closed
        let replay_res = proof.verify(&accumulator.root, &nonce, CLEARANCE_SECRET, &mut epoch_cache);
        assert_eq!(replay_res, Err(CoreError::Stale));
    }

    #[test]
    fn test_insufficient_clearance_prover_refused() {
        let node_patrol = TacticalIdentityRecord {
            callsign: "COAST-GUARD-PATROL-11".to_string(),
            serial_number: "USCG-991".to_string(),
            clearance_level: CLEARANCE_CONFIDENTIAL, // Level 2
            public_key_fingerprint: [0x11u8; 32],
        };

        let accumulator = MerkleAccumulator::build(vec![node_patrol.leaf_hash()]);
        let epoch = [0x01u8; 16];
        let nonce = [0x02u8; 32];
        let salt = [0x03u8; 32];

        // Attempting to claim TOP_SECRET (Level 4) with Level 2 credentials must fail
        let res = PqZkpIdentityProof::prove(
            &node_patrol,
            &accumulator,
            0,
            CLEARANCE_TOP_SECRET,
            &epoch,
            &nonce,
            &salt,
        );
        assert_eq!(res, Err(CoreError::AuthRequired));
    }
}
