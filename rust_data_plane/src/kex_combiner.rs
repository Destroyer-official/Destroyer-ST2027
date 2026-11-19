//! Multi-Assumption Post-Quantum KEX Combiner (Zero Fallback).
//!
//! Construction:
//! Combines ML-KEM-1024 (lattice-based, NIST FIPS 203, Cat-5),
//! Classic McEliece 8192128f (code-based, NIST Level 5), and an out-of-band
//! Hardware Pre-Shared Key (H-PSK, 256-bit).
//!
//! Security Invariant: Strict Triple-PRF AND-combiner.
//! K_master = HKDF-Extract(
//!     salt = SHA-384("ST2027-TRIPLE-KEX-v1" || Transcript),
//!     IKM  = SS_ML-KEM || SS_McEliece || K_H-PSK
//! )
//!
//! Zero fallback:
//! If either ciphertext or the PSK is missing or invalid, the combiner fails
//! closed immediately. Classical-only or unhybridized operation is strictly
//! refused. All secret buffers enforce `ZeroizeOnDrop` and branchless
//! constant-time comparisons.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ct::ct_eq;

type HmacSha384 = Hmac<Sha384>;

/// Domain separator for the Triple-KEX master key extraction.
pub const DOMAIN_TRIPLE_KEX: &[u8] = b"ST2027-TRIPLE-KEX-v1";
/// Domain separator for Initiator -> Responder traffic key expansion.
pub const DOMAIN_EXPAND_I2R: &[u8] = b"ST2027-TRIPLE-KEX-I2R-v1";
/// Domain separator for Responder -> Initiator traffic key expansion.
pub const DOMAIN_EXPAND_R2I: &[u8] = b"ST2027-TRIPLE-KEX-R2I-v1";
/// Domain separator for key confirmation root expansion.
pub const DOMAIN_EXPAND_CONFIRM: &[u8] = b"ST2027-TRIPLE-KEX-CONFIRM-v1";
/// Domain separator for initiator key confirmation tag.
pub const DOMAIN_CONFIRM_INITIATOR: &[u8] = b"ST2027-TRIPLE-KEX-CONFIRM-INITIATOR-v1";
/// Domain separator for responder key confirmation tag.
pub const DOMAIN_CONFIRM_RESPONDER: &[u8] = b"ST2027-TRIPLE-KEX-CONFIRM-RESPONDER-v1";

/// ML-KEM-1024 public key length (FIPS 203).
pub const MLKEM1024_PK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext length.
pub const MLKEM1024_CT_LEN: usize = 1568;
/// ML-KEM-1024 shared secret length.
pub const MLKEM1024_SS_LEN: usize = 32;

/// Classic McEliece 8192128f public key length (Level 5 Goppa code).
pub const MCELIECE8192128F_PK_LEN: usize = 1357824;
/// Classic McEliece 8192128f ciphertext length.
pub const MCELIECE8192128F_CT_LEN: usize = 208;
/// Classic McEliece 8192128f shared secret length.
pub const MCELIECE8192128F_SS_LEN: usize = 32;

/// Hardware PSK length (256-bit entropy).
pub const HPSK_LEN: usize = 32;

/// Combined ciphertext length (1568 + 208 = 1776 bytes).
pub const COMBINED_CT_LEN: usize = MLKEM1024_CT_LEN + MCELIECE8192128F_CT_LEN;

/// Combined shared secrets length (32 + 32 + 32 = 96 bytes).
pub const COMBINED_SS_LEN: usize = MLKEM1024_SS_LEN + MCELIECE8192128F_SS_LEN + HPSK_LEN;

/// Master key length from HKDF-SHA384 extract (HashLen = 48 bytes).
pub const MASTER_KEY_LEN: usize = 48;

/// Errors emitted by the Triple-KEX Combiner. Coarse and fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CombinerError {
    /// Missing or null ciphertext component.
    MissingCiphertext,
    /// Ciphertext length does not match pinned algorithm specification.
    InvalidCiphertextLength,
    /// Missing or null public key component.
    MissingPublicKey,
    /// Public key length does not match pinned algorithm specification.
    InvalidPublicKeyLength,
    /// Missing or null Hardware PSK.
    MissingPsk,
    /// Hardware PSK length does not match 32 bytes.
    InvalidPskLength,
    /// Key material or secret is all zeros (zero entropy / degenerate).
    AllZeroKeyMaterial,
    /// KEM decapsulation failed.
    DecapsulationFailed,
    /// Key confirmation tag mismatch (tampering or MITM detected).
    BadConfirmationTag,
    /// HKDF subkey expansion failed.
    ExpansionFailed,
    /// Fallback to classical or unhybridized cipher refused (Zero Fallback).
    ZeroFallbackRefused,
}

impl core::fmt::Display for CombinerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CombinerError::MissingCiphertext => write!(f, "missing ciphertext component (fail-closed)"),
            CombinerError::InvalidCiphertextLength => {
                write!(f, "invalid ciphertext length (fail-closed)")
            }
            CombinerError::MissingPublicKey => write!(f, "missing public key component (fail-closed)"),
            CombinerError::InvalidPublicKeyLength => {
                write!(f, "invalid public key length (fail-closed)")
            }
            CombinerError::MissingPsk => write!(f, "hardware PSK missing (zero fallback refused)"),
            CombinerError::InvalidPskLength => write!(f, "invalid hardware PSK length (want 32 bytes)"),
            CombinerError::AllZeroKeyMaterial => {
                write!(f, "all-zero key material rejected (fail-closed)")
            }
            CombinerError::DecapsulationFailed => write!(f, "KEM decapsulation failed (fail-closed)"),
            CombinerError::BadConfirmationTag => {
                write!(f, "key confirmation tag verification failed (fail-closed)")
            }
            CombinerError::ExpansionFailed => write!(f, "HKDF expansion failed"),
            CombinerError::ZeroFallbackRefused => {
                write!(f, "zero fallback invariant violated: all three legs required")
            }
        }
    }
}

impl std::error::Error for CombinerError {}

/// Branchless constant-time check: returns true iff buffer is all zeros.
#[inline(never)]
pub fn ct_is_all_zeros(buf: &[u8]) -> bool {
    let mut acc = 0u8;
    for &b in buf {
        acc |= b;
    }
    core::hint::black_box(acc) == 0
}

/// Out-of-band Hardware Pre-Shared Key (32 bytes).
/// Protected with `ZeroizeOnDrop` so secret bytes are wiped from RAM on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HardwarePsk {
    key: [u8; HPSK_LEN],
}

impl core::fmt::Debug for HardwarePsk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HardwarePsk([REDACTED])")
    }
}

impl HardwarePsk {
    pub fn new(key: [u8; HPSK_LEN]) -> Result<Self, CombinerError> {
        if ct_is_all_zeros(&key) {
            return Err(CombinerError::AllZeroKeyMaterial);
        }
        Ok(Self { key })
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, CombinerError> {
        if slice.len() != HPSK_LEN {
            return Err(CombinerError::InvalidPskLength);
        }
        let mut key = [0u8; HPSK_LEN];
        key.copy_from_slice(slice);
        Self::new(key)
    }

    pub fn as_bytes(&self) -> &[u8; HPSK_LEN] {
        &self.key
    }
}

/// Triple-KEX Public Key: ML-KEM-1024 public key (1568B) and Classic McEliece 8192128f (1357824B).
/// McEliece public key is heap-boxed to prevent kernel/userland thread stack overflows.
#[derive(Clone)]
pub struct TripleKexPublicKey {
    pub mlkem_pk: Box<[u8; MLKEM1024_PK_LEN]>,
    pub mceliece_pk: Box<[u8; MCELIECE8192128F_PK_LEN]>,
}

impl core::fmt::Debug for TripleKexPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "TripleKexPublicKey {{ mlkem_pk: [{} bytes], mceliece_pk: [{} bytes] }}",
            MLKEM1024_PK_LEN, MCELIECE8192128F_PK_LEN
        )
    }
}

impl PartialEq for TripleKexPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.mlkem_pk.as_ref() == other.mlkem_pk.as_ref()
            && self.mceliece_pk.as_ref() == other.mceliece_pk.as_ref()
    }
}

impl Eq for TripleKexPublicKey {}

impl TripleKexPublicKey {
    pub fn new(
        mlkem_pk: Box<[u8; MLKEM1024_PK_LEN]>,
        mceliece_pk: Box<[u8; MCELIECE8192128F_PK_LEN]>,
    ) -> Result<Self, CombinerError> {
        if ct_is_all_zeros(mlkem_pk.as_ref()) || ct_is_all_zeros(mceliece_pk.as_ref()) {
            return Err(CombinerError::AllZeroKeyMaterial);
        }
        Ok(Self {
            mlkem_pk,
            mceliece_pk,
        })
    }

    pub fn from_slices(mlkem: &[u8], mceliece: &[u8]) -> Result<Self, CombinerError> {
        if mlkem.len() != MLKEM1024_PK_LEN || mceliece.len() != MCELIECE8192128F_PK_LEN {
            return Err(CombinerError::InvalidPublicKeyLength);
        }
        let mut ml_box = Box::new([0u8; MLKEM1024_PK_LEN]);
        ml_box.copy_from_slice(mlkem);

        let mut mc_vec = vec![0u8; MCELIECE8192128F_PK_LEN];
        mc_vec.copy_from_slice(mceliece);
        let mc_box: Box<[u8; MCELIECE8192128F_PK_LEN]> = match mc_vec.into_boxed_slice().try_into() {
            Ok(b) => b,
            Err(_) => return Err(CombinerError::InvalidPublicKeyLength),
        };

        Self::new(ml_box, mc_box)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MLKEM1024_PK_LEN + MCELIECE8192128F_PK_LEN);
        out.extend_from_slice(self.mlkem_pk.as_ref());
        out.extend_from_slice(self.mceliece_pk.as_ref());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CombinerError> {
        if bytes.len() != MLKEM1024_PK_LEN + MCELIECE8192128F_PK_LEN {
            return Err(CombinerError::InvalidPublicKeyLength);
        }
        Self::from_slices(
            &bytes[..MLKEM1024_PK_LEN],
            &bytes[MLKEM1024_PK_LEN..],
        )
    }
}

/// Triple-KEX Ciphertext: ML-KEM-1024 ciphertext (1568B) and McEliece 8192128f ciphertext (208B).
/// Fixed wire length: 1776 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TripleKexCiphertext {
    pub mlkem_ct: [u8; MLKEM1024_CT_LEN],
    pub mceliece_ct: [u8; MCELIECE8192128F_CT_LEN],
}

impl TripleKexCiphertext {
    pub fn new(
        mlkem_ct: [u8; MLKEM1024_CT_LEN],
        mceliece_ct: [u8; MCELIECE8192128F_CT_LEN],
    ) -> Result<Self, CombinerError> {
        if ct_is_all_zeros(&mlkem_ct) || ct_is_all_zeros(&mceliece_ct) {
            return Err(CombinerError::AllZeroKeyMaterial);
        }
        Ok(Self {
            mlkem_ct,
            mceliece_ct,
        })
    }

    pub fn from_slices(mlkem: &[u8], mceliece: &[u8]) -> Result<Self, CombinerError> {
        if mlkem.len() != MLKEM1024_CT_LEN || mceliece.len() != MCELIECE8192128F_CT_LEN {
            return Err(CombinerError::InvalidCiphertextLength);
        }
        let mut ml = [0u8; MLKEM1024_CT_LEN];
        ml.copy_from_slice(mlkem);
        let mut mc = [0u8; MCELIECE8192128F_CT_LEN];
        mc.copy_from_slice(mceliece);
        Self::new(ml, mc)
    }

    pub fn to_bytes(&self) -> [u8; COMBINED_CT_LEN] {
        let mut out = [0u8; COMBINED_CT_LEN];
        out[..MLKEM1024_CT_LEN].copy_from_slice(&self.mlkem_ct);
        out[MLKEM1024_CT_LEN..].copy_from_slice(&self.mceliece_ct);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CombinerError> {
        if bytes.len() != COMBINED_CT_LEN {
            return Err(CombinerError::InvalidCiphertextLength);
        }
        Self::from_slices(
            &bytes[..MLKEM1024_CT_LEN],
            &bytes[MLKEM1024_CT_LEN..],
        )
    }
}

/// Secret material holder for the three shared secrets before combination.
/// Protected with `ZeroizeOnDrop`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TripleSharedSecrets {
    pub mlkem_ss: [u8; MLKEM1024_SS_LEN],
    pub mceliece_ss: [u8; MCELIECE8192128F_SS_LEN],
    pub h_psk: [u8; HPSK_LEN],
}

impl core::fmt::Debug for TripleSharedSecrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TripleSharedSecrets([REDACTED])")
    }
}

impl TripleSharedSecrets {
    pub fn new(
        mlkem_ss: [u8; MLKEM1024_SS_LEN],
        mceliece_ss: [u8; MCELIECE8192128F_SS_LEN],
        h_psk: [u8; HPSK_LEN],
    ) -> Result<Self, CombinerError> {
        if ct_is_all_zeros(&mlkem_ss)
            || ct_is_all_zeros(&mceliece_ss)
            || ct_is_all_zeros(&h_psk)
        {
            return Err(CombinerError::AllZeroKeyMaterial);
        }
        Ok(Self {
            mlkem_ss,
            mceliece_ss,
            h_psk,
        })
    }
}

/// Master Key (48 bytes) resulting from HKDF-SHA384 Extract.
/// Protected with `ZeroizeOnDrop`. Constant-time comparison supported.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key: [u8; MASTER_KEY_LEN],
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MasterKey([REDACTED])")
    }
}

impl MasterKey {
    pub fn new(key: [u8; MASTER_KEY_LEN]) -> Result<Self, CombinerError> {
        if ct_is_all_zeros(&key) {
            return Err(CombinerError::AllZeroKeyMaterial);
        }
        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.key
    }

    /// Constant-time branchless comparison.
    pub fn ct_eq(&self, other: &MasterKey) -> bool {
        ct_eq(&self.key, &other.key) && self.key.ct_eq(&other.key).into()
    }
}

/// Multi-Assumption Post-Quantum KEX Combiner (TripleKex).
pub struct TripleKex;

impl TripleKex {
    /// Derive $K_{\text{master}} = \text{HKDF-Extract}(\text{SHA384}(\text{"ST2027-TRIPLE-KEX-v1"} \parallel \text{Transcript}), SS_{\text{ML-KEM}} \parallel SS_{\text{McEliece}} \parallel K_{\text{H-PSK}})$.
    ///
    /// Strict Triple-PRF AND-combiner:
    /// - `ss_mlkem` must be non-zero 32 bytes
    /// - `ss_mceliece` must be non-zero 32 bytes
    /// - `h_psk` must be non-zero 32 bytes
    ///
    /// If ANY input is missing or invalid, fails closed immediately with `CombinerError`. Zero fallback.
    pub fn derive_master_key(
        transcript: &[u8],
        ss_mlkem: &[u8; MLKEM1024_SS_LEN],
        ss_mceliece: &[u8; MCELIECE8192128F_SS_LEN],
        h_psk: &[u8; HPSK_LEN],
    ) -> Result<MasterKey, CombinerError> {
        // Enforce constant-time non-zero checks on all secret inputs (zero fallback refused)
        if ct_is_all_zeros(ss_mlkem)
            || ct_is_all_zeros(ss_mceliece)
            || ct_is_all_zeros(h_psk)
        {
            return Err(CombinerError::AllZeroKeyMaterial);
        }

        // Salt = SHA-384("ST2027-TRIPLE-KEX-v1" || Transcript)
        let mut hasher = Sha384::new();
        hasher.update(DOMAIN_TRIPLE_KEX);
        hasher.update(transcript);
        let salt = hasher.finalize();

        // IKM = SS_ML-KEM || SS_McEliece || K_H-PSK (96 bytes)
        let mut ikm = Zeroizing::new([0u8; COMBINED_SS_LEN]);
        ikm[..MLKEM1024_SS_LEN].copy_from_slice(ss_mlkem);
        ikm[MLKEM1024_SS_LEN..MLKEM1024_SS_LEN + MCELIECE8192128F_SS_LEN]
            .copy_from_slice(ss_mceliece);
        ikm[MLKEM1024_SS_LEN + MCELIECE8192128F_SS_LEN..].copy_from_slice(h_psk);

        // HKDF-Extract(salt, IKM) -> PRK (48 bytes for SHA-384)
        let (prk, _) = Hkdf::<Sha384>::extract(Some(&salt[..]), &ikm[..]);
        let mut k_master = [0u8; MASTER_KEY_LEN];
        k_master.copy_from_slice(&prk);

        MasterKey::new(k_master)
    }

    /// Derive from encapsulated `TripleSharedSecrets`.
    pub fn derive_from_shared_secrets(
        transcript: &[u8],
        secrets: &TripleSharedSecrets,
    ) -> Result<MasterKey, CombinerError> {
        Self::derive_master_key(
            transcript,
            &secrets.mlkem_ss,
            &secrets.mceliece_ss,
            &secrets.h_psk,
        )
    }

    /// Expand MasterKey (48 bytes) into role-separated transport and confirmation keys:
    /// - `initiator_traffic_key`: 32 bytes (AES-256-GCM / FrameKey)
    /// - `responder_traffic_key`: 32 bytes (AES-256-GCM / FrameKey)
    /// - `confirmation_key`: 32 bytes (HMAC-SHA384 mutual confirmation tag key)
    pub fn expand_session_keys(
        master_key: &MasterKey,
        transcript_binding: &[u8],
    ) -> Result<TripleSessionKeys, CombinerError> {
        let hk = Hkdf::<Sha384>::from_prk(master_key.as_bytes())
            .map_err(|_| CombinerError::ExpansionFailed)?;

        let mut i2r_info = Vec::with_capacity(DOMAIN_EXPAND_I2R.len() + transcript_binding.len());
        i2r_info.extend_from_slice(DOMAIN_EXPAND_I2R);
        i2r_info.extend_from_slice(transcript_binding);

        let mut r2i_info = Vec::with_capacity(DOMAIN_EXPAND_R2I.len() + transcript_binding.len());
        r2i_info.extend_from_slice(DOMAIN_EXPAND_R2I);
        r2i_info.extend_from_slice(transcript_binding);

        let mut conf_info = Vec::with_capacity(DOMAIN_EXPAND_CONFIRM.len() + transcript_binding.len());
        conf_info.extend_from_slice(DOMAIN_EXPAND_CONFIRM);
        conf_info.extend_from_slice(transcript_binding);

        let mut i2r_key = [0u8; 32];
        hk.expand(&i2r_info, &mut i2r_key)
            .map_err(|_| CombinerError::ExpansionFailed)?;

        let mut r2i_key = [0u8; 32];
        hk.expand(&r2i_info, &mut r2i_key)
            .map_err(|_| CombinerError::ExpansionFailed)?;

        let mut conf_key = [0u8; 32];
        hk.expand(&conf_info, &mut conf_key)
            .map_err(|_| CombinerError::ExpansionFailed)?;

        Ok(TripleSessionKeys {
            initiator_traffic_key: i2r_key,
            responder_traffic_key: r2i_key,
            confirmation_key: conf_key,
        })
    }

    /// Compute mutual key confirmation tag via HMAC-SHA384(confirmation_key, role_label || transcript).
    pub fn compute_confirmation_tag(
        confirmation_key: &[u8; 32],
        role_label: &[u8],
        transcript_binding: &[u8],
    ) -> Result<[u8; 32], CombinerError> {
        if ct_is_all_zeros(confirmation_key) {
            return Err(CombinerError::AllZeroKeyMaterial);
        }
        let mut mac = HmacSha384::new_from_slice(confirmation_key)
            .map_err(|_| CombinerError::ExpansionFailed)?;
        mac.update(role_label);
        mac.update(transcript_binding);
        let full = mac.finalize().into_bytes();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&full[..32]);
        Ok(tag)
    }

    /// Constant-time branchless verification of peer key confirmation tag.
    pub fn verify_confirmation_tag(
        confirmation_key: &[u8; 32],
        role_label: &[u8],
        transcript_binding: &[u8],
        expected_tag: &[u8; 32],
    ) -> Result<(), CombinerError> {
        let computed = Self::compute_confirmation_tag(confirmation_key, role_label, transcript_binding)?;
        if !ct_eq(&computed, expected_tag) || !bool::from(computed.ct_eq(expected_tag)) {
            return Err(CombinerError::BadConfirmationTag);
        }
        Ok(())
    }
}

/// Role-separated transport traffic keys and confirmation key.
/// Zeroized automatically on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TripleSessionKeys {
    pub initiator_traffic_key: [u8; 32],
    pub responder_traffic_key: [u8; 32],
    pub confirmation_key: [u8; 32],
}

impl core::fmt::Debug for TripleSessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TripleSessionKeys([REDACTED])")
    }
}

impl TripleSessionKeys {
    /// Constant-time branchless comparison across all three derived session keys.
    pub fn ct_eq(&self, other: &TripleSessionKeys) -> bool {
        ct_eq(&self.initiator_traffic_key, &other.initiator_traffic_key)
            && ct_eq(&self.responder_traffic_key, &other.responder_traffic_key)
            && ct_eq(&self.confirmation_key, &other.confirmation_key)
            && bool::from(self.initiator_traffic_key.ct_eq(&other.initiator_traffic_key))
            && bool::from(self.responder_traffic_key.ct_eq(&other.responder_traffic_key))
            && bool::from(self.confirmation_key.ct_eq(&other.confirmation_key))
    }
}

impl PartialEq for TripleSessionKeys {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for TripleSessionKeys {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_triple_kex_derivation_deterministic() {
        let transcript = b"TEST-TRANSCRIPT-SESSION-ALPHA";
        let ss_mlkem = [0x11u8; 32];
        let ss_mceliece = [0x22u8; 32];
        let h_psk = [0x33u8; 32];

        let k1 = TripleKex::derive_master_key(transcript, &ss_mlkem, &ss_mceliece, &h_psk).unwrap();
        let k2 = TripleKex::derive_master_key(transcript, &ss_mlkem, &ss_mceliece, &h_psk).unwrap();

        assert_eq!(k1.as_bytes(), k2.as_bytes());
        assert!(k1.ct_eq(&k2));
        assert_eq!(k1.as_bytes().len(), 48);
    }

    #[test]
    fn test_cross_language_known_vector() {
        let transcript = b"TEST-TRANSCRIPT-VECTOR-999";
        let ss_mlkem = [0x11u8; 32];
        let ss_mceliece = [0x22u8; 32];
        let h_psk = [0x33u8; 32];

        let k = TripleKex::derive_master_key(transcript, &ss_mlkem, &ss_mceliece, &h_psk).unwrap();
        let hex_str = k.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(
            hex_str,
            "cfb1aaa2081c4549345df71afdb4726974b29662980a3834f444338e9c514f5b626b80f908476ab80557ab6bfd1c8712"
        );
    }

    #[test]
    fn test_triple_kex_zero_fallback_refused_all_zero_inputs() {
        let transcript = b"TEST-TRANSCRIPT";
        let zero_32 = [0u8; 32];
        let valid_32 = [0x42u8; 32];

        // Zero ML-KEM
        assert_eq!(
            TripleKex::derive_master_key(transcript, &zero_32, &valid_32, &valid_32).unwrap_err(),
            CombinerError::AllZeroKeyMaterial
        );

        // Zero McEliece
        assert_eq!(
            TripleKex::derive_master_key(transcript, &valid_32, &zero_32, &valid_32).unwrap_err(),
            CombinerError::AllZeroKeyMaterial
        );

        // Zero PSK
        assert_eq!(
            TripleKex::derive_master_key(transcript, &valid_32, &valid_32, &zero_32).unwrap_err(),
            CombinerError::AllZeroKeyMaterial
        );
    }

    #[test]
    fn test_triple_kex_any_secret_change_alters_master() {
        let transcript = b"TEST-TRANSCRIPT";
        let ss_ml = [0x01u8; 32];
        let ss_mc = [0x02u8; 32];
        let h_psk = [0x03u8; 32];

        let base = TripleKex::derive_master_key(transcript, &ss_ml, &ss_mc, &h_psk).unwrap();

        // Mutate ML-KEM
        let mut ss_ml_mut = ss_ml;
        ss_ml_mut[0] ^= 0x80;
        let diff_ml = TripleKex::derive_master_key(transcript, &ss_ml_mut, &ss_mc, &h_psk).unwrap();
        assert_ne!(base.as_bytes(), diff_ml.as_bytes());

        // Mutate McEliece
        let mut ss_mc_mut = ss_mc;
        ss_mc_mut[0] ^= 0x80;
        let diff_mc = TripleKex::derive_master_key(transcript, &ss_ml, &ss_mc_mut, &h_psk).unwrap();
        assert_ne!(base.as_bytes(), diff_mc.as_bytes());

        // Mutate PSK
        let mut psk_mut = h_psk;
        psk_mut[0] ^= 0x80;
        let diff_psk = TripleKex::derive_master_key(transcript, &ss_ml, &ss_mc, &psk_mut).unwrap();
        assert_ne!(base.as_bytes(), diff_psk.as_bytes());

        // Mutate transcript
        let diff_tr = TripleKex::derive_master_key(b"DIFFERENT", &ss_ml, &ss_mc, &h_psk).unwrap();
        assert_ne!(base.as_bytes(), diff_tr.as_bytes());
    }

    #[test]
    fn test_triple_kex_ciphertext_wire_roundtrip() {
        let ml_ct = [0xAAu8; MLKEM1024_CT_LEN];
        let mc_ct = [0xBBu8; MCELIECE8192128F_CT_LEN];

        let ct = TripleKexCiphertext::new(ml_ct, mc_ct).unwrap();
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), COMBINED_CT_LEN);

        let parsed = TripleKexCiphertext::from_bytes(&bytes).unwrap();
        assert_eq!(ct, parsed);

        // Truncated fails closed
        assert_eq!(
            TripleKexCiphertext::from_bytes(&bytes[..COMBINED_CT_LEN - 1]).unwrap_err(),
            CombinerError::InvalidCiphertextLength
        );
    }

    #[test]
    fn test_hardware_psk_validation() {
        assert!(HardwarePsk::from_slice(&[0u8; 31]).is_err());
        assert!(HardwarePsk::from_slice(&[0u8; 33]).is_err());
        assert!(HardwarePsk::from_slice(&[0u8; 32]).is_err()); // all zeros
        assert!(HardwarePsk::from_slice(&[0xFFu8; 32]).is_ok());
    }

    #[test]
    fn test_session_keys_expansion_and_confirmation() {
        let transcript = b"TEST-TRANSCRIPT";
        let ss_ml = [0x01u8; 32];
        let ss_mc = [0x02u8; 32];
        let h_psk = [0x03u8; 32];

        let master = TripleKex::derive_master_key(transcript, &ss_ml, &ss_mc, &h_psk).unwrap();
        let session_keys = TripleKex::expand_session_keys(&master, transcript).unwrap();

        assert_ne!(session_keys.initiator_traffic_key, session_keys.responder_traffic_key);
        assert_ne!(session_keys.initiator_traffic_key, session_keys.confirmation_key);

        let init_tag = TripleKex::compute_confirmation_tag(
            &session_keys.confirmation_key,
            DOMAIN_CONFIRM_INITIATOR,
            transcript,
        ).unwrap();

        let resp_tag = TripleKex::compute_confirmation_tag(
            &session_keys.confirmation_key,
            DOMAIN_CONFIRM_RESPONDER,
            transcript,
        ).unwrap();

        assert_ne!(init_tag, resp_tag);

        assert!(TripleKex::verify_confirmation_tag(
            &session_keys.confirmation_key,
            DOMAIN_CONFIRM_INITIATOR,
            transcript,
            &init_tag,
        ).is_ok());

        let mut bad_tag = init_tag;
        bad_tag[0] ^= 0xFF;
        assert_eq!(
            TripleKex::verify_confirmation_tag(
                &session_keys.confirmation_key,
                DOMAIN_CONFIRM_INITIATOR,
                transcript,
                &bad_tag,
            ).unwrap_err(),
            CombinerError::BadConfirmationTag
        );
    }

    #[test]
    fn test_public_key_debug_and_eq() {
        let mut ml = vec![0x42u8; MLKEM1024_PK_LEN];
        let mc = vec![0x43u8; MCELIECE8192128F_PK_LEN];

        let pk1 = TripleKexPublicKey::from_slices(&ml, &mc).unwrap();
        let pk2 = TripleKexPublicKey::from_slices(&ml, &mc).unwrap();

        assert_eq!(pk1, pk2);
        assert_eq!(format!("{:?}", pk1), "TripleKexPublicKey { mlkem_pk: [1568 bytes], mceliece_pk: [1357824 bytes] }");

        ml[0] ^= 0x01;
        let pk3 = TripleKexPublicKey::from_slices(&ml, &mc).unwrap();
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn test_triple_session_keys_ct_eq() {
        let transcript = b"SESSION-CT-EQ-TEST";
        let ss_ml = [0x55u8; 32];
        let ss_mc = [0x66u8; 32];
        let h_psk = [0x77u8; 32];

        let master = TripleKex::derive_master_key(transcript, &ss_ml, &ss_mc, &h_psk).unwrap();
        let k1 = TripleKex::expand_session_keys(&master, transcript).unwrap();
        let k2 = TripleKex::expand_session_keys(&master, transcript).unwrap();

        assert!(k1.ct_eq(&k2));
        assert_eq!(k1, k2);

        let mut k3 = k1.clone();
        k3.initiator_traffic_key[0] ^= 0x01;
        assert!(!k1.ct_eq(&k3));
        assert_ne!(k1, k3);
    }
}
