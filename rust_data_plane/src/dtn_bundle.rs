//! Asynchronous DTN & 0-RTT Post-Quantum Mesh (RFC 9171 BPv7 + ML-KEM-1024)
//!
//! Provides delay-tolerant networking (DTN) bundle encapsulation for contested,
//! disrupted space-to-ground, and subterranean links. Implements RFC 9171
//! Bundle Protocol Version 7 (BPv7) with zero-round-trip (0-RTT) post-quantum
//! cryptographic envelopes (FIPS 203 ML-KEM-1024 + FIPS 204 ML-DSA-87).
//!
//! Invariants:
//! 1. No interactive handshake required (0-RTT simplex forward security).
//! 2. Hop limits strictly enforced to prevent routing loops in store-and-forward mesh.
//! 3. Cryptographic lifetime binding: expired bundles are dropped fail-closed.
//! 4. Source authenticity: primary + security headers bound and signed with ML-DSA-87.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, KeyExport, SharedKey},
    Ciphertext, DecapsulationKey, Kem, MlKem1024, Seed,
};
use sha2::Sha512;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::auth::{AuthSigner, Mldsa87SigningKey, Mldsa87VerifyingKey};
use crate::ct::ct_eq;
use crate::kem::{MLKEM_CT, MLKEM_PK};
use crate::policy::{CoreError, MLDSA87_PK, MLDSA87_SIG};

/// RFC 9171 Magic Wire Header for Post-Quantum DTN Bundles.
pub const DTN_MAGIC: &[u8; 6] = b"BP7PQC";

/// RFC 9171 Bundle Protocol Version.
pub const BP_VERSION_7: u8 = 7;

/// Processing control flags (RFC 9171 Section 4.2.3).
pub const FLAG_IS_FRAGMENT: u64 = 0x0001;
pub const FLAG_ADMIN_RECORD: u64 = 0x0002;
pub const FLAG_NOT_FRAGMENTED: u64 = 0x0004;
pub const FLAG_ACK_REQUESTED: u64 = 0x0020;
pub const FLAG_STATUS_REPORT: u64 = 0x0040;
pub const FLAG_CUSTODY_TRANSFER: u64 = 0x0800;

/// Default bundle lifetime: 86400 seconds (24 hours).
pub const DEFAULT_BUNDLE_LIFETIME_MS: u64 = 86_400_000;

/// Default hop limit for mesh propagation.
pub const DEFAULT_HOP_LIMIT: u32 = 32;

/// Domain separation tags.
const DOMAIN_0RTT_KDF: &[u8] = b"RFC9171-BPv7-0RTT-MLKEM1024-AES256GCM";
const DOMAIN_0RTT_SIGN: &[u8] = b"RFC9171-BPv7-0RTT-SIGNATURE-MLDSA87:";

/// ML-KEM-1024 Keypair container for DTN node identity.
pub struct DtnMlKemKeypair {
    pub dk: DecapsulationKey<MlKem1024>,
    pub ek_bytes: Vec<u8>,
}

impl DtnMlKemKeypair {
    /// Generate a fresh ML-KEM-1024 keypair.
    pub fn generate() -> Result<Self, CoreError> {
        let (dk, ek) = MlKem1024::generate_keypair();
        let ek_bytes = ek.to_bytes().to_vec();
        if ek_bytes.len() != MLKEM_PK {
            return Err(CoreError::Malformed);
        }
        Ok(Self { dk, ek_bytes })
    }

    /// Reconstruct an ML-KEM-1024 decapsulation key strictly from a 64-byte FIPS 203 seed.
    pub fn decapsulation_key_from_seed(
        seed_bytes: &[u8],
    ) -> Result<DecapsulationKey<MlKem1024>, CoreError> {
        if seed_bytes.len() != 64 {
            return Err(CoreError::Malformed);
        }
        let mut seed = Seed::default();
        seed.copy_from_slice(seed_bytes);
        let dk = DecapsulationKey::<MlKem1024>::from_seed(seed);
        seed.zeroize();
        Ok(dk)
    }

    /// Export the 64-byte FIPS 203 ML-KEM-1024 seed bytes wrapped in `Zeroizing`.
    pub fn dk_seed_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.dk.to_bytes().as_slice().to_vec())
    }
}

/// RFC 9171 Creation Timestamp (ms since 2000-01-01T00:00:00Z, sequence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DtnCreationTimestamp {
    pub time_ms: u64,
    pub sequence: u64,
}

/// RFC 9171 Primary Block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtnPrimaryBlock {
    pub version: u8,
    pub flags: u64,
    pub crc_type: u8,
    pub destination_eid: String,
    pub source_eid: String,
    pub report_to_eid: String,
    pub creation_time: DtnCreationTimestamp,
    pub lifetime_ms: u64,
}

impl DtnPrimaryBlock {
    /// Compute SHA3-256 canonical hash of the primary block for transcript binding.
    pub fn transcript_hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update([self.version, self.crc_type]);
        hasher.update(self.flags.to_be_bytes());
        hasher.update((self.destination_eid.len() as u16).to_be_bytes());
        hasher.update(self.destination_eid.as_bytes());
        hasher.update((self.source_eid.len() as u16).to_be_bytes());
        hasher.update(self.source_eid.as_bytes());
        hasher.update((self.report_to_eid.len() as u16).to_be_bytes());
        hasher.update(self.report_to_eid.as_bytes());
        hasher.update(self.creation_time.time_ms.to_be_bytes());
        hasher.update(self.creation_time.sequence.to_be_bytes());
        hasher.update(self.lifetime_ms.to_be_bytes());
        hasher.finalize().into()
    }
}

/// RFC 9171 Hop Count Canonical Block (Block Type 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtnHopCountBlock {
    pub hop_limit: u32,
    pub hop_count: u32,
}

/// RFC 9171 Bundle Age Canonical Block (Block Type 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtnBundleAgeBlock {
    pub age_ms: u64,
}

/// 0-RTT Post-Quantum Security Block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dtn0RttSecurityBlock {
    pub kem_ct: Vec<u8>,              // 1568 bytes (ML-KEM-1024)
    pub nonce: [u8; 12],              // 12 bytes AES-GCM nonce
    pub ciphertext: Vec<u8>,          // Encrypted payload + 16B auth tag
    pub sender_mldsa_pub: Vec<u8>,    // 2592 bytes (ML-DSA-87 public key)
    pub mldsa_signature: Vec<u8>,     // 4627 bytes (ML-DSA-87 signature)
}

/// Custody Transfer Signal / Admin Record Status (RFC 9171 Section 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CustodySignalStatus {
    CustodyAccepted = 0x01,
    CustodyRefused = 0x02,
    DeliveredToApplication = 0x03,
    LifetimeExpired = 0x04,
    HopLimitExceeded = 0x05,
    DepletedStorage = 0x06,
}

/// Represents an RFC 9171 Post-Quantum DTN Bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtnBundle {
    pub primary: DtnPrimaryBlock,
    pub hop_count: DtnHopCountBlock,
    pub bundle_age: DtnBundleAgeBlock,
    pub previous_node: Option<String>,
    pub security: Option<Dtn0RttSecurityBlock>,
    pub payload: Option<Vec<u8>>,
}

impl DtnBundle {
    /// Constructs a unique Bundle ID string: `<source_eid>/<time_ms>-<sequence>`.
    pub fn bundle_id(&self) -> String {
        format!(
            "{}/{}-{}",
            self.primary.source_eid,
            self.primary.creation_time.time_ms,
            self.primary.creation_time.sequence
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_0rtt_with<F>(
        source_eid: &str,
        destination_eid: &str,
        report_to_eid: &str,
        creation_time_ms: u64,
        sequence: u64,
        lifetime_ms: u64,
        hop_limit: u32,
        recipient_mlkem_pk: &[u8],
        sender_mldsa_pk: &[u8],
        sign_fn: F,
        payload: &[u8],
    ) -> Result<Self, CoreError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, CoreError>,
    {
        if recipient_mlkem_pk.len() != MLKEM_PK {
            return Err(CoreError::Malformed);
        }
        if sender_mldsa_pk.len() != MLDSA87_PK {
            return Err(CoreError::Malformed);
        }

        // 1. Construct Primary Block
        let primary = DtnPrimaryBlock {
            version: BP_VERSION_7,
            flags: FLAG_NOT_FRAGMENTED | FLAG_CUSTODY_TRANSFER | FLAG_STATUS_REPORT,
            crc_type: 3, // SHA3
            destination_eid: destination_eid.to_string(),
            source_eid: source_eid.to_string(),
            report_to_eid: report_to_eid.to_string(),
            creation_time: DtnCreationTimestamp {
                time_ms: creation_time_ms,
                sequence,
            },
            lifetime_ms: if lifetime_ms == 0 {
                DEFAULT_BUNDLE_LIFETIME_MS
            } else {
                lifetime_ms
            },
        };

        let primary_hash = primary.transcript_hash();

        // 2. Perform 0-RTT ML-KEM-1024 Encapsulation to recipient's static public key
        let (kem_ct, shared_secret) = crate::kem::encapsulate_mlkem(recipient_mlkem_pk)
            .map_err(|_| CoreError::Malformed)?;

        // 3. HKDF-SHA512 Key Derivation bound to Primary Block Hash
        let hk = Hkdf::<Sha512>::new(Some(&primary_hash), shared_secret.as_slice());
        let mut okm = [0u8; 44]; // 32 bytes AES-256 key + 12 bytes nonce
        hk.expand(DOMAIN_0RTT_KDF, &mut okm)
            .map_err(|_| CoreError::Malformed)?;

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&okm[..32]);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&okm[32..44]);
        okm.zeroize();

        // 4. Encrypt payload with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| CoreError::Malformed)?;
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: payload, aad: &primary_hash })
            .map_err(|_| CoreError::Malformed)?;
        key_bytes.zeroize();

        // 5. ML-DSA-87 Digital Signature over (Domain || Primary Hash || KEM CT || Nonce || Ciphertext)
        let mut sig_msg = Vec::with_capacity(32 + MLKEM_CT + 12 + ciphertext.len());
        sig_msg.extend_from_slice(&primary_hash);
        sig_msg.extend_from_slice(&kem_ct);
        sig_msg.extend_from_slice(&nonce_bytes);
        sig_msg.extend_from_slice(&ciphertext);

        let signature = sign_fn(&sig_msg)?;
        if signature.len() != MLDSA87_SIG {
            return Err(CoreError::Malformed);
        }

        let security = Dtn0RttSecurityBlock {
            kem_ct,
            nonce: nonce_bytes,
            ciphertext,
            sender_mldsa_pub: sender_mldsa_pk.to_vec(),
            mldsa_signature: signature,
        };

        Ok(Self {
            primary,
            hop_count: DtnHopCountBlock {
                hop_limit,
                hop_count: 0,
            },
            bundle_age: DtnBundleAgeBlock { age_ms: 0 },
            previous_node: None,
            security: Some(security),
            payload: None, // Sealed in security block
        })
    }

    /// Creates an asynchronous 0-RTT post-quantum encrypted bundle using ML-KEM-1024 and ML-DSA-87.
    #[allow(clippy::too_many_arguments)]
    pub fn create_0rtt(
        source_eid: &str,
        destination_eid: &str,
        report_to_eid: &str,
        creation_time_ms: u64,
        sequence: u64,
        lifetime_ms: u64,
        hop_limit: u32,
        recipient_mlkem_pk: &[u8],
        sender_mldsa_sk: &Mldsa87SigningKey,
        sender_mldsa_pk: &[u8],
        payload: &[u8],
    ) -> Result<Self, CoreError> {
        Self::seal_0rtt_with(
            source_eid,
            destination_eid,
            report_to_eid,
            creation_time_ms,
            sequence,
            lifetime_ms,
            hop_limit,
            recipient_mlkem_pk,
            sender_mldsa_pk,
            |msg| Ok(sender_mldsa_sk.sign(DOMAIN_0RTT_SIGN, msg)),
            payload,
        )
    }

    /// Creates an asynchronous 0-RTT post-quantum encrypted bundle using hardware-agnostic `AuthSigner`
    /// (PKCS#11 HSM, TPM 2.0 PCR-unsealed key, or ML-DSA-87 signing key).
    #[allow(clippy::too_many_arguments)]
    pub fn create_0rtt_with_signer(
        source_eid: &str,
        destination_eid: &str,
        report_to_eid: &str,
        creation_time_ms: u64,
        sequence: u64,
        lifetime_ms: u64,
        hop_limit: u32,
        recipient_mlkem_pk: &[u8],
        signer: &AuthSigner,
        payload: &[u8],
    ) -> Result<Self, CoreError> {
        let sender_pk = signer.verifying_bytes();
        Self::seal_0rtt_with(
            source_eid,
            destination_eid,
            report_to_eid,
            creation_time_ms,
            sequence,
            lifetime_ms,
            hop_limit,
            recipient_mlkem_pk,
            &sender_pk,
            |msg| signer.sign(DOMAIN_0RTT_SIGN, msg),
            payload,
        )
    }

    /// Opens an incoming 0-RTT post-quantum bundle AND enforces constant-time
    /// pinning of the sender's 2592-byte ML-DSA-87 verifying key BEFORE decapsulation.
    pub fn open_0rtt_pinned(
        &self,
        recipient_dk: &DecapsulationKey<MlKem1024>,
        expected_sender_mldsa_pk: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        if expected_sender_mldsa_pk.len() != MLDSA87_PK {
            return Err(CoreError::Malformed);
        }
        let sec = self.security.as_ref().ok_or(CoreError::Malformed)?;
        if sec.sender_mldsa_pub.len() != MLDSA87_PK {
            return Err(CoreError::Malformed);
        }
        if !ct_eq(&sec.sender_mldsa_pub, expected_sender_mldsa_pk) {
            return Err(CoreError::KeyMismatch);
        }
        self.open_0rtt(recipient_dk)
    }

    /// Opens an incoming 0-RTT post-quantum bundle using the recipient's ML-KEM-1024 decapsulation key.
    pub fn open_0rtt(
        &self,
        recipient_dk: &DecapsulationKey<MlKem1024>,
    ) -> Result<Vec<u8>, CoreError> {
        let sec = self.security.as_ref().ok_or(CoreError::Malformed)?;
        if sec.kem_ct.len() != MLKEM_CT || sec.sender_mldsa_pub.len() != MLDSA87_PK || sec.mldsa_signature.len() != MLDSA87_SIG {
            return Err(CoreError::Malformed);
        }

        // 1. Verify ML-DSA-87 signature first (authenticate sender before decapsulation)
        let sender_vk = Mldsa87VerifyingKey::from_bytes(&sec.sender_mldsa_pub)?;
        let primary_hash = self.primary.transcript_hash();

        let mut sig_msg = Vec::with_capacity(32 + MLKEM_CT + 12 + sec.ciphertext.len());
        sig_msg.extend_from_slice(&primary_hash);
        sig_msg.extend_from_slice(&sec.kem_ct);
        sig_msg.extend_from_slice(&sec.nonce);
        sig_msg.extend_from_slice(&sec.ciphertext);

        sender_vk.verify(DOMAIN_0RTT_SIGN, &sig_msg, &sec.mldsa_signature)?;

        // 2. Decapsulate ML-KEM-1024 shared secret
        let ct_arr: [u8; MLKEM_CT] = sec.kem_ct.as_slice().try_into().map_err(|_| CoreError::Malformed)?;
        let ct: Ciphertext<MlKem1024> = ct_arr.into();
        let shared_secret: SharedKey<MlKem1024> = recipient_dk.decapsulate(&ct);

        // 3. HKDF-SHA512 Key Derivation
        let hk = Hkdf::<Sha512>::new(Some(&primary_hash), shared_secret.as_slice());
        let mut okm = [0u8; 44];
        hk.expand(DOMAIN_0RTT_KDF, &mut okm)
            .map_err(|_| CoreError::Malformed)?;

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&okm[..32]);
        let mut expected_nonce = [0u8; 12];
        expected_nonce.copy_from_slice(&okm[32..44]);
        okm.zeroize();

        // Nonce verification
        if sec.nonce != expected_nonce {
            key_bytes.zeroize();
            return Err(CoreError::NonceMismatch);
        }

        // 4. Decrypt payload with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| CoreError::Malformed)?;
        let nonce = Nonce::from(sec.nonce);
        let plaintext = cipher
            .decrypt(&nonce, Payload { msg: &sec.ciphertext, aad: &primary_hash })
            .map_err(|_| CoreError::Malformed)?;
        key_bytes.zeroize();

        Ok(plaintext)
    }

    /// Advances hop count and verifies store-and-forward routing constraints:
    /// - Checks whether lifetime has expired.
    /// - Increments hop count and verifies `hop_count <= hop_limit`.
    /// - Updates bundle age and previous node EID.
    pub fn process_hop(
        &mut self,
        current_time_ms: u64,
        hop_transit_time_ms: u64,
        current_node_eid: &str,
    ) -> Result<(), CoreError> {
        // 1. Lifetime check
        let expiration = self.primary.creation_time.time_ms.saturating_add(self.primary.lifetime_ms);
        if current_time_ms > expiration {
            return Err(CoreError::Stale);
        }

        // 2. Hop limit check
        if self.hop_count.hop_count >= self.hop_count.hop_limit {
            return Err(CoreError::Oversize); // Hop limit exceeded
        }

        // 3. Advance state
        self.hop_count.hop_count = self.hop_count.hop_count.saturating_add(1);
        self.bundle_age.age_ms = self.bundle_age.age_ms.saturating_add(hop_transit_time_ms);
        self.previous_node = Some(current_node_eid.to_string());

        Ok(())
    }

    /// Creates an RFC 9171 Administrative Record Custody Signal.
    pub fn create_custody_signal(
        reporting_node_eid: &str,
        subject_bundle: &DtnBundle,
        status: CustodySignalStatus,
        current_time_ms: u64,
    ) -> Self {
        let mut payload = Vec::with_capacity(64);
        payload.push(status as u8);
        payload.extend_from_slice(&subject_bundle.primary.creation_time.time_ms.to_be_bytes());
        payload.extend_from_slice(&subject_bundle.primary.creation_time.sequence.to_be_bytes());
        let src_bytes = subject_bundle.primary.source_eid.as_bytes();
        payload.extend_from_slice(&(src_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(src_bytes);

        let primary = DtnPrimaryBlock {
            version: BP_VERSION_7,
            flags: FLAG_ADMIN_RECORD | FLAG_NOT_FRAGMENTED,
            crc_type: 0,
            destination_eid: subject_bundle.primary.report_to_eid.clone(),
            source_eid: reporting_node_eid.to_string(),
            report_to_eid: reporting_node_eid.to_string(),
            creation_time: DtnCreationTimestamp {
                time_ms: current_time_ms,
                sequence: 1,
            },
            lifetime_ms: DEFAULT_BUNDLE_LIFETIME_MS,
        };

        Self {
            primary,
            hop_count: DtnHopCountBlock {
                hop_limit: 16,
                hop_count: 0,
            },
            bundle_age: DtnBundleAgeBlock { age_ms: 0 },
            previous_node: None,
            security: None,
            payload: Some(payload),
        }
    }

    /// Serializes the bundle into RFC 9171 Post-Quantum Wire Format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(DTN_MAGIC);
        out.push(self.primary.version);
        out.extend_from_slice(&self.primary.flags.to_be_bytes());
        out.push(self.primary.crc_type);

        // Destination EID
        let dst = self.primary.destination_eid.as_bytes();
        out.extend_from_slice(&(dst.len() as u16).to_be_bytes());
        out.extend_from_slice(dst);

        // Source EID
        let src = self.primary.source_eid.as_bytes();
        out.extend_from_slice(&(src.len() as u16).to_be_bytes());
        out.extend_from_slice(src);

        // Report-To EID
        let rep = self.primary.report_to_eid.as_bytes();
        out.extend_from_slice(&(rep.len() as u16).to_be_bytes());
        out.extend_from_slice(rep);

        // Creation Time & Lifetime
        out.extend_from_slice(&self.primary.creation_time.time_ms.to_be_bytes());
        out.extend_from_slice(&self.primary.creation_time.sequence.to_be_bytes());
        out.extend_from_slice(&self.primary.lifetime_ms.to_be_bytes());

        // Canonical Blocks
        out.extend_from_slice(&self.hop_count.hop_limit.to_be_bytes());
        out.extend_from_slice(&self.hop_count.hop_count.to_be_bytes());
        out.extend_from_slice(&self.bundle_age.age_ms.to_be_bytes());

        // Previous Node
        if let Some(ref pn) = self.previous_node {
            out.push(1);
            let pn_bytes = pn.as_bytes();
            out.extend_from_slice(&(pn_bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(pn_bytes);
        } else {
            out.push(0);
        }

        // Security Block or Raw Payload
        if let Some(ref sec) = self.security {
            out.push(1); // 1 = 0-RTT Security Block present
            out.extend_from_slice(&sec.kem_ct);
            out.extend_from_slice(&sec.nonce);
            out.extend_from_slice(&(sec.ciphertext.len() as u32).to_be_bytes());
            out.extend_from_slice(&sec.ciphertext);
            out.extend_from_slice(&sec.sender_mldsa_pub);
            out.extend_from_slice(&sec.mldsa_signature);
        } else {
            out.push(0); // 0 = Plain payload
            let pl = self.payload.as_deref().unwrap_or(&[]);
            out.extend_from_slice(&(pl.len() as u32).to_be_bytes());
            out.extend_from_slice(pl);
        }

        out
    }

    /// Deserializes a bundle from RFC 9171 Post-Quantum Wire Format.
    pub fn from_bytes(wire: &[u8]) -> Result<Self, CoreError> {
        if wire.len() < 50 || &wire[..6] != DTN_MAGIC {
            return Err(CoreError::Malformed);
        }
        let mut offset = 6;

        let version = wire[offset];
        offset += 1;
        if version != BP_VERSION_7 {
            return Err(CoreError::Malformed);
        }

        let flags = u64::from_be_bytes(
            wire[offset..offset + 8].try_into().map_err(|_| CoreError::Malformed)?
        );
        offset += 8;

        let crc_type = wire[offset];
        offset += 1;

        // Destination EID
        let dst_len = u16::from_be_bytes(
            wire[offset..offset + 2].try_into().map_err(|_| CoreError::Malformed)?
        ) as usize;
        offset += 2;
        if offset + dst_len > wire.len() {
            return Err(CoreError::Malformed);
        }
        let destination_eid = std::str::from_utf8(&wire[offset..offset + dst_len])
            .map_err(|_| CoreError::Malformed)?
            .to_string();
        offset += dst_len;

        // Source EID
        let src_len = u16::from_be_bytes(
            wire[offset..offset + 2].try_into().map_err(|_| CoreError::Malformed)?
        ) as usize;
        offset += 2;
        if offset + src_len > wire.len() {
            return Err(CoreError::Malformed);
        }
        let source_eid = std::str::from_utf8(&wire[offset..offset + src_len])
            .map_err(|_| CoreError::Malformed)?
            .to_string();
        offset += src_len;

        // Report-To EID
        let rep_len = u16::from_be_bytes(
            wire[offset..offset + 2].try_into().map_err(|_| CoreError::Malformed)?
        ) as usize;
        offset += 2;
        if offset + rep_len > wire.len() {
            return Err(CoreError::Malformed);
        }
        let report_to_eid = std::str::from_utf8(&wire[offset..offset + rep_len])
            .map_err(|_| CoreError::Malformed)?
            .to_string();
        offset += rep_len;

        // Creation Time & Lifetime
        let time_ms = u64::from_be_bytes(
            wire[offset..offset + 8].try_into().map_err(|_| CoreError::Malformed)?
        );
        offset += 8;
        let sequence = u64::from_be_bytes(
            wire[offset..offset + 8].try_into().map_err(|_| CoreError::Malformed)?
        );
        offset += 8;
        let lifetime_ms = u64::from_be_bytes(
            wire[offset..offset + 8].try_into().map_err(|_| CoreError::Malformed)?
        );
        offset += 8;

        // Canonical Blocks
        let hop_limit = u32::from_be_bytes(
            wire[offset..offset + 4].try_into().map_err(|_| CoreError::Malformed)?
        );
        offset += 4;
        let hop_count = u32::from_be_bytes(
            wire[offset..offset + 4].try_into().map_err(|_| CoreError::Malformed)?
        );
        offset += 4;
        let age_ms = u64::from_be_bytes(
            wire[offset..offset + 8].try_into().map_err(|_| CoreError::Malformed)?
        );
        offset += 8;

        // Previous Node
        let pn_flag = wire[offset];
        offset += 1;
        let previous_node = if pn_flag == 1 {
            let pn_len = u16::from_be_bytes(
                wire[offset..offset + 2].try_into().map_err(|_| CoreError::Malformed)?
            ) as usize;
            offset += 2;
            if offset + pn_len > wire.len() {
                return Err(CoreError::Malformed);
            }
            let pn = std::str::from_utf8(&wire[offset..offset + pn_len])
                .map_err(|_| CoreError::Malformed)?
                .to_string();
            offset += pn_len;
            Some(pn)
        } else {
            None
        };

        // Security Block or Payload
        let sec_flag = wire[offset];
        offset += 1;

        let (security, payload) = if sec_flag == 1 {
            if offset + MLKEM_CT + 12 + 4 > wire.len() {
                return Err(CoreError::Malformed);
            }
            let kem_ct = wire[offset..offset + MLKEM_CT].to_vec();
            offset += MLKEM_CT;

            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&wire[offset..offset + 12]);
            offset += 12;

            let ct_len = u32::from_be_bytes(
                wire[offset..offset + 4].try_into().map_err(|_| CoreError::Malformed)?
            ) as usize;
            offset += 4;

            if offset + ct_len + MLDSA87_PK + MLDSA87_SIG > wire.len() {
                return Err(CoreError::Malformed);
            }
            let ciphertext = wire[offset..offset + ct_len].to_vec();
            offset += ct_len;

            let sender_mldsa_pub = wire[offset..offset + MLDSA87_PK].to_vec();
            offset += MLDSA87_PK;

            let mldsa_signature = wire[offset..offset + MLDSA87_SIG].to_vec();

            (
                Some(Dtn0RttSecurityBlock {
                    kem_ct,
                    nonce,
                    ciphertext,
                    sender_mldsa_pub,
                    mldsa_signature,
                }),
                None,
            )
        } else {
            let pl_len = u32::from_be_bytes(
                wire[offset..offset + 4].try_into().map_err(|_| CoreError::Malformed)?
            ) as usize;
            offset += 4;
            if offset + pl_len > wire.len() {
                return Err(CoreError::Malformed);
            }
            let payload = wire[offset..offset + pl_len].to_vec();
            (None, Some(payload))
        };

        Ok(Self {
            primary: DtnPrimaryBlock {
                version,
                flags,
                crc_type,
                destination_eid,
                source_eid,
                report_to_eid,
                creation_time: DtnCreationTimestamp { time_ms, sequence },
                lifetime_ms,
            },
            hop_count: DtnHopCountBlock { hop_limit, hop_count },
            bundle_age: DtnBundleAgeBlock { age_ms },
            previous_node,
            security,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_0rtt_bundle_roundtrip() {
        // Setup recipient ML-KEM-1024 keypair
        let recipient_keypair = DtnMlKemKeypair::generate().unwrap();

        // Setup sender ML-DSA-87 signing keypair
        let (sender_sk, sender_vk) = Mldsa87SigningKey::generate().unwrap();
        let sender_pk = sender_vk.to_bytes();

        let payload = b"STRATCOM-EAM-DIRECTIVE-ALPHA-7782";

        let bundle = DtnBundle::create_0rtt(
            "dtn://norad-silo-01/command",
            "dtn://stratcom-sub-04/ops",
            "dtn://norad-silo-01/reports",
            1700000000000,
            42,
            3600000,
            16,
            &recipient_keypair.ek_bytes,
            &sender_sk,
            &sender_pk,
            payload,
        )
        .unwrap();

        // Serialize to wire
        let wire = bundle.to_bytes();

        // Deserialize from wire
        let deserialized = DtnBundle::from_bytes(&wire).unwrap();
        assert_eq!(deserialized.primary.source_eid, "dtn://norad-silo-01/command");
        assert_eq!(deserialized.primary.destination_eid, "dtn://stratcom-sub-04/ops");
        assert_eq!(deserialized.hop_count.hop_limit, 16);
        assert_eq!(deserialized.hop_count.hop_count, 0);

        // Open 0-RTT envelope
        let decrypted = deserialized.open_0rtt(&recipient_keypair.dk).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_hop_limit_enforcement() {
        let recipient_keypair = DtnMlKemKeypair::generate().unwrap();
        let (sender_sk, sender_vk) = Mldsa87SigningKey::generate().unwrap();

        let mut bundle = DtnBundle::create_0rtt(
            "dtn://ground-station-1",
            "dtn://sat-relay-9",
            "dtn://ground-station-1/rep",
            1700000000000,
            1,
            3600000,
            2, // Hop limit 2
            &recipient_keypair.ek_bytes,
            &sender_sk,
            &sender_vk.to_bytes(),
            b"test",
        )
        .unwrap();

        assert!(bundle.process_hop(1700000001000, 50, "dtn://relay-node-1").is_ok());
        assert_eq!(bundle.hop_count.hop_count, 1);

        assert!(bundle.process_hop(1700000002000, 60, "dtn://relay-node-2").is_ok());
        assert_eq!(bundle.hop_count.hop_count, 2);

        // Third hop must fail closed because hop_count (2) >= hop_limit (2)
        let res = bundle.process_hop(1700000003000, 40, "dtn://relay-node-3");
        assert!(res.is_err());
    }

    #[test]
    fn test_lifetime_expiration() {
        let recipient_keypair = DtnMlKemKeypair::generate().unwrap();
        let (sender_sk, sender_vk) = Mldsa87SigningKey::generate().unwrap();

        let mut bundle = DtnBundle::create_0rtt(
            "dtn://ground-station-1",
            "dtn://sat-relay-9",
            "dtn://ground-station-1/rep",
            1700000000000,
            1,
            5000, // 5 second lifetime
            10,
            &recipient_keypair.ek_bytes,
            &sender_sk,
            &sender_vk.to_bytes(),
            b"test",
        )
        .unwrap();

        // 6 seconds later -> expired
        let res = bundle.process_hop(1700000006000, 10, "dtn://relay-node-1");
        assert_eq!(res, Err(CoreError::Stale));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let recipient_keypair = DtnMlKemKeypair::generate().unwrap();
        let (sender_sk, sender_vk) = Mldsa87SigningKey::generate().unwrap();

        let mut bundle = DtnBundle::create_0rtt(
            "dtn://ground-station-1",
            "dtn://sat-relay-9",
            "dtn://ground-station-1/rep",
            1700000000000,
            1,
            60000,
            10,
            &recipient_keypair.ek_bytes,
            &sender_sk,
            &sender_vk.to_bytes(),
            b"test",
        )
        .unwrap();

        // Tamper with ciphertext
        if let Some(ref mut sec) = bundle.security {
            sec.ciphertext[0] ^= 0xFF;
        }

        let res = bundle.open_0rtt(&recipient_keypair.dk);
        assert!(res.is_err());
    }

    #[test]
    fn test_dk_serialization() {
        let (dk, _ek) = MlKem1024::generate_keypair();
        let seed = dk.to_bytes();
        assert_eq!(seed.len(), 64);
        let dk2 = DecapsulationKey::<MlKem1024>::new(&seed);
        assert_eq!(dk2.to_bytes().as_slice(), seed.as_slice());
        let dk3 = DtnMlKemKeypair::decapsulation_key_from_seed(seed.as_slice()).unwrap();
        assert_eq!(dk3.to_bytes().as_slice(), seed.as_slice());
    }

    #[test]
    fn test_open_0rtt_pinned_rejects_spoofed_sender() {
        let recipient = DtnMlKemKeypair::generate().unwrap();
        let (good_sk, good_vk) = Mldsa87SigningKey::generate().unwrap();
        let (attacker_sk, _attacker_vk) = Mldsa87SigningKey::generate().unwrap();

        let forged = DtnBundle::create_0rtt_with_signer(
            "dtn://spoof",
            "dtn://dest",
            "dtn://spoof/rep",
            1700000000000,
            7,
            60000,
            8,
            &recipient.ek_bytes,
            &AuthSigner::SoftwareOrTpmUnsealed(attacker_sk),
            b"spoofed payload",
        )
        .unwrap();

        assert_eq!(
            forged.open_0rtt_pinned(&recipient.dk, &good_vk.to_bytes()),
            Err(CoreError::KeyMismatch)
        );

        let authentic = DtnBundle::create_0rtt_with_signer(
            "dtn://alpha",
            "dtn://bravo",
            "dtn://alpha/rep",
            1700000000000,
            8,
            60000,
            8,
            &recipient.ek_bytes,
            &AuthSigner::SoftwareOrTpmUnsealed(good_sk),
            b"authentic 0rtt dead-drop",
        )
        .unwrap();

        assert_eq!(
            authentic
                .open_0rtt_pinned(&recipient.dk, &good_vk.to_bytes())
                .unwrap(),
            b"authentic 0rtt dead-drop"
        );
    }
}
