//! Native ML-DSA-87 authentication (FIPS 204, CNSA 2.0).
//!
//! This is the Rust-core replacement for the Python `liboqs` ML-DSA path.
//! Pure-Rust `ml-dsa` crate (FIPS 204 final); no `oqs.dll`, no ctypes, no
//! interpreter copies. Reference behavior mirrors `noise_pq.py` (role-
//! separated signature domains, verify-before-derive) and `ts_attest.py`
//! (enrollment-bound verification), but secrets live in Rust types with
//! verified wiping (`SigningKey` implements wiping `Drop` upstream) and
//! every comparison is constant-time (`crate::ct::ct_eq`).
//!
//! Honesty: upstream `ml-dsa`/`ml-kem` crates state they are unaudited —
//! honored here via pinned KAT sizes, cross-checks against the Python
//! liboqs reference path, and fail-closed malformed-input refusal.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, KeyExport, Keypair, MlDsa87, Signature,
    SignatureEncoding, Signer, SigningKey, Verifier, VerifyingKey,
};

use crate::ct::ct_eq;
use crate::policy::{CoreError, DOMAIN_SIG_INITIATOR, DOMAIN_SIG_RESPONDER, MLDSA87_PK, MLDSA87_SIG};

/// ML-DSA-87 signing key. The inner `SigningKey` wipes itself on drop
/// (upstream `Drop` impl); this wrapper never exposes it.
pub struct Mldsa87SigningKey {
    inner: SigningKey<MlDsa87>,
}

impl Mldsa87SigningKey {
    /// Generate a fresh keypair from OS randomness.
    pub fn generate() -> Result<(Self, Mldsa87VerifyingKey), CoreError> {
        let sk = SigningKey::<MlDsa87>::generate();
        let vk = sk.verifying_key().clone();
        Ok((Self { inner: sk }, Mldsa87VerifyingKey { inner: vk }))
    }

    /// Sign `domain || message`. Domain MUST be a role-separated constant
    /// from `crate::policy` (prevents cross-role reflection).
    pub fn sign(&self, domain: &[u8], message: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(domain.len() + message.len());
        m.extend_from_slice(domain);
        m.extend_from_slice(message);
        let sig: Signature<MlDsa87> = self.inner.sign(&m);
        sig.to_bytes().to_vec()
    }

    /// Export the verifying key bytes (2592, FIPS 204).
    pub fn verifying_bytes(&self) -> Vec<u8> {
        self.inner.verifying_key().to_bytes().to_vec()
    }
}

/// ML-DSA-87 verifying key (public, enrolled out-of-band).
#[derive(Debug, Clone)]
pub struct Mldsa87VerifyingKey {
    inner: VerifyingKey<MlDsa87>,
}

impl Mldsa87VerifyingKey {
    /// Parse enrolled public bytes. Exact length required (fail-closed).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != MLDSA87_PK {
            return Err(CoreError::Malformed);
        }
        let arr: [u8; MLDSA87_PK] = bytes.try_into().map_err(|_| CoreError::Malformed)?;
        let enc: EncodedVerifyingKey<MlDsa87> = arr.into();
        let inner = VerifyingKey::<MlDsa87>::decode(&enc);
        Ok(Self { inner })
    }

    /// Canonical encoded bytes (for enrollment-pin comparison).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Verify `domain || message` against `sig_bytes`. Fixed-size sig only.
    pub fn verify(&self, domain: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<(), CoreError> {
        if sig_bytes.len() != MLDSA87_SIG {
            return Err(CoreError::Malformed);
        }
        let arr: [u8; MLDSA87_SIG] = sig_bytes.try_into().map_err(|_| CoreError::Malformed)?;
        let enc: EncodedSignature<MlDsa87> = arr.into();
        let sig = Signature::<MlDsa87>::decode(&enc).ok_or(CoreError::Malformed)?;
        let mut m = Vec::with_capacity(domain.len() + message.len());
        m.extend_from_slice(domain);
        m.extend_from_slice(message);
        self.inner.verify(&m, &sig).map_err(|_| CoreError::BadSignature)
    }

    /// Constant-time enrollment-pin equality (for trust-anchor stores).
    pub fn ct_pin_eq(&self, enrolled_bytes: &[u8]) -> bool {
        ct_eq(&self.to_bytes(), enrolled_bytes)
    }
}

/// Convenience: responder-side sign over a handshake transcript hash.
pub fn sign_responder(sk: &Mldsa87SigningKey, transcript: &[u8; 48]) -> Vec<u8> {
    sk.sign(DOMAIN_SIG_RESPONDER, transcript)
}

/// Convenience: initiator-side sign over a handshake transcript hash.
pub fn sign_initiator(sk: &Mldsa87SigningKey, transcript: &[u8; 48]) -> Vec<u8> {
    sk.sign(DOMAIN_SIG_INITIATOR, transcript)
}

/// Convenience: verify-before-derive gate for the responder leg.
pub fn verify_responder(
    vk: &Mldsa87VerifyingKey,
    transcript: &[u8; 48],
    sig: &[u8],
) -> Result<(), CoreError> {
    vk.verify(DOMAIN_SIG_RESPONDER, transcript, sig)
}

/// Convenience: verify-before-derive gate for the initiator leg.
pub fn verify_initiator(
    vk: &Mldsa87VerifyingKey,
    transcript: &[u8; 48],
    sig: &[u8],
) -> Result<(), CoreError> {
    vk.verify(DOMAIN_SIG_INITIATOR, transcript, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_role_separation() {
        let (sk, vk) = Mldsa87SigningKey::generate().expect("keygen");
        let t = [0xA5u8; 48];
        let sr = sign_responder(&sk, &t);
        let si = sign_initiator(&sk, &t);
        assert_eq!(sr.len(), MLDSA87_SIG);
        // Correct roles verify.
        verify_responder(&vk, &t, &sr).expect("responder leg");
        verify_initiator(&vk, &t, &si).expect("initiator leg");
        // Cross-role reflection refused.
        assert!(verify_initiator(&vk, &t, &sr).is_err());
        assert!(verify_responder(&vk, &t, &si).is_err());
        // Tampered transcript refused.
        let mut t2 = t;
        t2[0] ^= 1;
        assert!(verify_responder(&vk, &t2, &sr).is_err());
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        let (_, vk) = Mldsa87SigningKey::generate().expect("keygen");
        let t = [0u8; 48];
        assert_eq!(vk.verify(DOMAIN_SIG_RESPONDER, &t, &[0u8; 10]).unwrap_err(), CoreError::Malformed);
        assert!(Mldsa87VerifyingKey::from_bytes(&[0u8; 100]).is_err());
        // Pin encode round-trips through enrollment parse.
        let raw = vk.to_bytes();
        assert_eq!(raw.len(), MLDSA87_PK);
        let vk2 = Mldsa87VerifyingKey::from_bytes(&raw).expect("reparse");
        assert!(vk2.ct_pin_eq(&raw));
        // Enrollment pin compare is constant-time equality, not pointer eq.
        let mut other = raw.clone();
        other[0] = other[0].wrapping_add(1);
        // NOTE: re-parsed key still compares against the ORIGINAL pin only.
        assert!(!vk2.ct_pin_eq(&other));
    }
}
