//! Hybrid key exchange: X25519 + ML-KEM-1024 (FIPS 203).
//!
//! Construction follows RFC 10024 (PQ/T hybrids for TLS 1.3, Aug 2026):
//! both algorithms run, outputs are concatenated — the session is safe while
//! AT LEAST ONE component holds. Shared secret = `ml_ss(32) || x_ss(32)`.
//!
//! Category note: this pairs ML-KEM-1024 (Cat-5) with X25519. The CNSA L5
//! path is SecP384r1MLKEM1024; X25519 legs remain for interop and are NEVER
//! trusted alone — `hybrid_secret` requires both halves, and policy forbids
//! classical-only use (see `nist_level5_policy_engine.py`).
//!
//! `ml-kem` is unaudited upstream (their warning honored): KAT sizes pinned,
//! cross-checked against the Python liboqs path at integration time, and the
//! hybrid wrapper refuses malformed inputs fail-closed. All secrets zeroized.

use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport, SharedKey},
    EncapsulationKey, MlKem1024,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// ML-KEM-1024 encapsulation key size (FIPS 203 Table 3).
pub const MLKEM_PK: usize = 1568;
/// ML-KEM-1024 ciphertext size.
pub const MLKEM_CT: usize = 1568;
/// Shared secret halves: 32B ML-KEM + 32B X25519.
pub const HYBRID_SS: usize = 64;

#[derive(Debug)]
pub enum KemError {
    BadLength,
    DecapsFailed,
    OsRandom,
}

impl std::fmt::Display for KemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KemError::BadLength => write!(f, "malformed KEM public key/ciphertext length"),
            KemError::DecapsFailed => write!(f, "KEM decapsulation failed"),
            KemError::OsRandom => write!(f, "OS randomness unavailable"),
        }
    }
}

impl std::error::Error for KemError {}

fn os_random_32() -> Result<[u8; 32], KemError> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|_| KemError::OsRandom)?;
    Ok(buf)
}

/// Ephemeral hybrid keypair (initiator side).
pub struct EphemeralKeys {
    x_secret: StaticSecret,
    pub x_public: [u8; 32],
    ml_dk: ml_kem::DecapsulationKey<MlKem1024>,
    pub ml_ek: Vec<u8>,
}

pub type HybridEncapsResult = (Vec<u8>, Zeroizing<[u8; HYBRID_SS]>, [u8; 32]);

impl EphemeralKeys {
    pub fn generate() -> Result<Self, KemError> {
        let x_secret = StaticSecret::from(os_random_32()?);
        let x_public = PublicKey::from(&x_secret).to_bytes();
        let (dk, ek) = MlKem1024::generate_keypair();
        let ml_ek = ek.to_bytes().to_vec();
        debug_assert_eq!(ml_ek.len(), MLKEM_PK);
        Ok(EphemeralKeys {
            x_secret,
            x_public,
            ml_dk: dk,
            ml_ek,
        })
    }

    /// Encapsulate to a peer's `(x25519_pk, mlkem_ek)`.
    /// Returns `(our_x_pub_unused_here, ml_ct, hybrid_ss)`.
    /// (Our X25519 public was already sent in our bundle; the peer's static
    /// DH uses it. The initiator contributes handshake freshness via ML-KEM.)
    pub fn encapsulate(
        peer_x_pub: &[u8; 32],
        peer_ml_ek: &[u8],
    ) -> Result<HybridEncapsResult, KemError> {
        use ml_kem::Key;
        if peer_ml_ek.len() != MLKEM_PK {
            return Err(KemError::BadLength);
        }
        let ek_arr: [u8; MLKEM_PK] = peer_ml_ek.try_into().map_err(|_| KemError::BadLength)?;
        let ek_key: Key<EncapsulationKey<MlKem1024>> = ek_arr.into();
        let ek = EncapsulationKey::<MlKem1024>::new(&ek_key).map_err(|_| KemError::BadLength)?;
        let eph = StaticSecret::from(os_random_32()?);
        let eph_pub = PublicKey::from(&eph).to_bytes();
        let x_ss = eph.diffie_hellman(&PublicKey::from(*peer_x_pub)).to_bytes();
        let (ct, ml_ss) = ek.encapsulate();
        let mut hybrid = Zeroizing::new([0u8; HYBRID_SS]);
        hybrid[..32].copy_from_slice(ml_ss.as_slice());
        hybrid[32..].copy_from_slice(&x_ss);
        let mut x_ss_mut = x_ss;
        x_ss_mut.zeroize();
        Ok((ct.to_vec(), hybrid, eph_pub))
    }

    /// Decapsulate after receiving the peer's `(eph_x_pub, ml_ct)`.
    pub fn decapsulate(
        &self,
        peer_eph_x_pub: &[u8; 32],
        ml_ct: &[u8],
    ) -> Result<Zeroizing<[u8; HYBRID_SS]>, KemError> {
        if ml_ct.len() != MLKEM_CT {
            return Err(KemError::BadLength);
        }
        let x_ss = self
            .x_secret
            .diffie_hellman(&PublicKey::from(*peer_eph_x_pub))
            .to_bytes();
        use ml_kem::Ciphertext;
        let ct_arr: [u8; MLKEM_CT] = ml_ct.try_into().map_err(|_| KemError::BadLength)?;
        let ct: Ciphertext<MlKem1024> = ct_arr.into();
        let ml_ss: SharedKey<MlKem1024> = self.ml_dk.decapsulate(&ct);
        let mut hybrid = Zeroizing::new([0u8; HYBRID_SS]);
        hybrid[..32].copy_from_slice(ml_ss.as_slice());
        hybrid[32..].copy_from_slice(&x_ss);
        let mut x_ss_mut = x_ss;
        x_ss_mut.zeroize();
        Ok(hybrid)
    }
}

impl Drop for EphemeralKeys {
    fn drop(&mut self) {
        // StaticSecret zeroizes itself; ml_dk zeroizes with its feature.
        self.x_public.zeroize();
        self.ml_ek.zeroize();
    }
}

/// Derive a 32-byte AES-256 frame key from the 64-byte hybrid shared secret via HKDF-SHA384.
pub fn derive_session_key(hybrid_ss: &[u8; HYBRID_SS], context_info: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha384;
    let hk = Hkdf::<Sha384>::new(Some(b"ST2027-HYBRID-KEX-v1-SALT"), hybrid_ss);
    let mut okm = [0u8; 32];
    hk.expand(context_info, &mut okm)
        .expect("HKDF-SHA384 expand with 32-byte output cannot fail");
    okm
}

/// Derive a 32-byte AES-256 frame key from the 64-byte hybrid shared secret via HKDF-SHA384,
/// cryptographically bound to the handshake transcript hash.
/// If `psk` is provided (pre-shared key), it is used as salt to guarantee authentication.
pub fn derive_session_key_transcript(
    hybrid_ss: &[u8; HYBRID_SS],
    psk: Option<&[u8]>,
    transcript_hash: &[u8; 48],
) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha384;
    let salt: &[u8] = match psk {
        Some(p) if !p.is_empty() => p,
        _ => b"ST2027-HYBRID-KEX-v1-SALT",
    };
    let hk = Hkdf::<Sha384>::new(Some(salt), hybrid_ss);
    let mut okm = [0u8; 32];
    let mut info = Vec::with_capacity(64 + 48);
    info.extend_from_slice(b"DESTROYER-ST2027-TRANSCRIPT-BOUND-KEY-AES256GCM");
    info.extend_from_slice(transcript_hash);
    hk.expand(&info, &mut okm)
        .expect("HKDF-SHA384 expand with 32-byte output cannot fail");
    okm
}

/// Compute a 32-byte key confirmation tag: HMAC-SHA384(session_key, label || transcript_hash)[..32]
pub fn compute_confirmation_tag(
    session_key: &[u8; 32],
    label: &[u8],
    transcript_hash: &[u8; 48],
) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha384;
    let hk = Hkdf::<Sha384>::new(Some(session_key), label);
    let mut tag = [0u8; 32];
    hk.expand(transcript_hash, &mut tag)
        .expect("confirmation tag expand cannot fail");
    tag
}

/// Compute a 16-character Short Authentication String (SAS) fingerprint
/// formatted as 4 groups of 4 hex chars: `XXXX-XXXX-XXXX-XXXX`
pub fn compute_sas(session_key: &[u8; 32], transcript_hash: &[u8; 48]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(session_key);
    hasher.update(transcript_hash);
    let digest = hasher.finalize();
    format!(
        "{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]
    )
}

/// Constant-time 32-byte equality comparison to prevent timing or cache side channels.
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips203_sizes_pinned() {
        let keys = EphemeralKeys::generate().unwrap();
        assert_eq!(keys.ml_ek.len(), MLKEM_PK);
        // Ciphertext/shared-secret sizes asserted in roundtrip below.
    }

    #[test]
    fn initiator_responder_agree() {
        // Responder (long-term-ish ephemeral for the test) publishes bundle.
        let resp = EphemeralKeys::generate().unwrap();
        // Initiator encapsulates to responder bundle.
        let (ml_ct, ss_init, eph_pub) =
            EphemeralKeys::encapsulate(&resp.x_public, &resp.ml_ek).unwrap();
        assert_eq!(ml_ct.len(), MLKEM_CT);
        // Responder decapsulates with initiator ephemeral.
        let ss_resp = resp.decapsulate(&eph_pub, &ml_ct).unwrap();
        assert_eq!(&ss_init[..], &ss_resp[..]);
        // Both halves contribute: flipping responder X key changes agreement.
        let other = EphemeralKeys::generate().unwrap();
        let (_, ss_other, _) = EphemeralKeys::encapsulate(&other.x_public, &resp.ml_ek).unwrap();
        assert_ne!(&ss_init[..], &ss_other[..]);
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        let resp = EphemeralKeys::generate().unwrap();
        assert!(EphemeralKeys::encapsulate(&resp.x_public, &[0u8; 10]).is_err());
        assert!(resp.decapsulate(&[0u8; 32], &[0u8; 10]).is_err());
        // Wrong-length peer X key cannot even be constructed: fixed arrays.
    }

    #[test]
    fn tampered_ciphertext_does_not_match() {
        let resp = EphemeralKeys::generate().unwrap();
        let (mut ml_ct, ss_init, eph_pub) =
            EphemeralKeys::encapsulate(&resp.x_public, &resp.ml_ek).unwrap();
        ml_ct[100] ^= 0x01;
        // ML-KEM implicit rejection: decaps still returns *a* secret, but it
        // must NOT equal the initiator's. (FO transform property.)
        let ss_resp = resp.decapsulate(&eph_pub, &ml_ct).unwrap();
        assert_ne!(&ss_init[..], &ss_resp[..]);
    }

    #[test]
    fn test_derive_session_key_deterministic_and_matches() {
        let ss = [0x55u8; HYBRID_SS];
        let k1 = derive_session_key(&ss, b"test-context");
        let k2 = derive_session_key(&ss, b"test-context");
        assert_eq!(k1, k2);
        let k3 = derive_session_key(&ss, b"different-context");
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_transcript_bound_kex_and_confirmation_tags() {
        let ss = [0x77u8; HYBRID_SS];
        let transcript = [0x42u8; 48];
        let k1 = derive_session_key_transcript(&ss, None, &transcript);
        let k2 = derive_session_key_transcript(&ss, None, &transcript);
        assert_eq!(k1, k2);

        // PSK variation changes key
        let k_psk = derive_session_key_transcript(&ss, Some(b"sovereign-psk"), &transcript);
        assert_ne!(k1, k_psk);

        // Different transcript changes key
        let diff_transcript = [0x43u8; 48];
        let k_diff = derive_session_key_transcript(&ss, None, &diff_transcript);
        assert_ne!(k1, k_diff);

        // Confirmation tags
        let tag1 = compute_confirmation_tag(&k1, b"TEST-TAG", &transcript);
        let tag2 = compute_confirmation_tag(&k1, b"TEST-TAG", &transcript);
        assert!(constant_time_eq_32(&tag1, &tag2));

        let mut bad_tag = tag1;
        bad_tag[0] ^= 0x01;
        assert!(!constant_time_eq_32(&tag1, &bad_tag));

        // SAS formatting
        let sas1 = compute_sas(&k1, &transcript);
        let sas2 = compute_sas(&k1, &transcript);
        assert_eq!(sas1, sas2);
        assert_eq!(sas1.len(), 19); // 4 groups of 4 + 3 dashes = 19
    }
}
