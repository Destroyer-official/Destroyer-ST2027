//! Authenticated hybrid KEX session (Rust secure core).
//!
//! Wire-identical bundle layout to the existing data-plane KEX
//! (`main.rs` kex-listen/connect) and the Python reference
//! (`noise_pq.py` transcript discipline, `secure_transmit_2027.py`
//! verify-before-derive):
//!
//! ```text
//! responder_bundle = x_pub(32) || ml_ek(1568)
//! initiator_bundle = eph_x_pub(32) || ml_ct(1568)
//! transcript       = SHA-384(responder_bundle || initiator_bundle)
//! session_key      = HKDF-SHA384(hybrid_ss || psk?, salt, info || transcript)
//! ```
//!
//! Fail-closed authentication (no unauthenticated mode exists here):
//! every session requires a 32-byte PSK, a verified ML-DSA-87 transcript
//! signature chain, or both. `AuthMaterial::None` cannot be constructed
//! by public API — the type only exposes authenticated constructors.
//! SAS (first 16 bytes of SHA-384(session_key || transcript), hex
//! `XXXX-...`) MUST still be compared out-of-band before use; the code
//! returns it but never auto-trusts it.
//!
//! KEM-binding note (Fiedler/Guenther PKC 2025; Bhargavan USENIX 2024):
//! the transcript covers BOTH bundles (both encapsulation keys and the
//! ciphertext), and the KDF input binds the transcript, so a
//! re-encapsulation / key-substitution attacker cannot fork the session
//! without changing the derived key and the SAS.

use hkdf::Hkdf;
use sha2::{Digest, Sha384};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::auth::{Mldsa87VerifyingKey, verify_initiator, verify_responder};
use crate::kem::{EphemeralKeys, HYBRID_SS};
use crate::policy::{
    CoreError, DOMAIN_KEX_SESSION, MLKEM1024_CT, MLKEM1024_PK, SAS_LEN, TRANSCRIPT_LEN, X25519_PK,
};

/// Bundle: responder `x_pub || ml_ek`. Fixed 1600 bytes.
pub const RESPONDER_BUNDLE_LEN: usize = X25519_PK + MLKEM1024_PK;
/// Bundle: initiator `eph_x_pub || ml_ct`. Fixed 1600 bytes.
pub const INITIATOR_BUNDLE_LEN: usize = X25519_PK + MLKEM1024_CT;

/// Authenticated auth material. `None` is unrepresentable: callers must
/// supply PSK, ML-DSA legs, or both.
pub enum AuthMaterial<'a> {
    /// 32-byte pre-shared key (provisioned via file/stdin, never argv).
    Psk(&'a [u8; 32]),
    /// ML-DSA transcript-signature legs (both directions verified).
    Signatures {
        responder_vk: &'a Mldsa87VerifyingKey,
        responder_sig: &'a [u8],
        initiator_vk: &'a Mldsa87VerifyingKey,
        initiator_sig: &'a [u8],
    },
    /// PSK plus both ML-DSA legs (highest assurance).
    Both {
        psk: &'a [u8; 32],
        responder_vk: &'a Mldsa87VerifyingKey,
        responder_sig: &'a [u8],
        initiator_vk: &'a Mldsa87VerifyingKey,
        initiator_sig: &'a [u8],
    },
}

/// Established session: 32-byte frame key (zeroized), transcript, SAS.
#[derive(ZeroizeOnDrop)]
pub struct KexSession {
    session_key: [u8; 32],
    transcript: [u8; TRANSCRIPT_LEN],
    sas: [u8; SAS_LEN],
}

impl KexSession {
    /// Borrow the session key for a single copy-out (e.g. into `FrameKey`).
    pub fn session_key(&self) -> &[u8; 32] {
        &self.session_key
    }
    /// Transcript hash (binds both bundles).
    pub fn transcript(&self) -> &[u8; TRANSCRIPT_LEN] {
        &self.transcript
    }
    /// SAS bytes (compare out-of-band; never auto-trust).
    pub fn sas(&self) -> &[u8; SAS_LEN] {
        &self.sas
    }
    /// SAS as `XXXX-XXXX-XXXX-XXXX` hex (constant-length, no secret branch).
    pub fn sas_string(&self) -> String {
        const H: &[u8; 16] = b"0123456789ABCDEF";
        let mut s = String::with_capacity(19);
        for (i, b) in self.sas.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                s.push('-');
            }
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 15) as usize] as char);
        }
        s
    }
}

/// Transcript = SHA-384(responder_bundle || initiator_bundle).
pub fn transcript(responder_bundle: &[u8], initiator_bundle: &[u8]) -> Result<[u8; TRANSCRIPT_LEN], CoreError> {
    if responder_bundle.len() != RESPONDER_BUNDLE_LEN || initiator_bundle.len() != INITIATOR_BUNDLE_LEN {
        return Err(CoreError::Malformed);
    }
    let mut h = Sha384::new();
    h.update(responder_bundle);
    h.update(initiator_bundle);
    let d = h.finalize();
    let mut t = [0u8; TRANSCRIPT_LEN];
    t.copy_from_slice(&d);
    Ok(t)
}

/// Verify-before-derive: both ML-DSA transcript signatures MUST verify
/// before ANY key is derived. Returns `BadSignature` (coarse) on failure.
fn verify_sig_legs(
    transcript: &[u8; TRANSCRIPT_LEN],
    responder_vk: &Mldsa87VerifyingKey,
    responder_sig: &[u8],
    initiator_vk: &Mldsa87VerifyingKey,
    initiator_sig: &[u8],
) -> Result<(), CoreError> {
    verify_responder(responder_vk, transcript, responder_sig)?;
    verify_initiator(initiator_vk, transcript, initiator_sig)?;
    Ok(())
}

/// Derive session key bound to transcript (+PSK salt when present).
fn derive(transcript: &[u8; TRANSCRIPT_LEN], hybrid_ss: &[u8; HYBRID_SS], psk: Option<&[u8; 32]>) -> ([u8; 32], [u8; SAS_LEN]) {
    let salt: &[u8] = match psk {
        Some(p) => &p[..],
        None => DOMAIN_KEX_SESSION,
    };
    let hk = Hkdf::<Sha384>::new(Some(salt), hybrid_ss);
    let mut info = Vec::with_capacity(DOMAIN_KEX_SESSION.len() + TRANSCRIPT_LEN);
    info.extend_from_slice(DOMAIN_KEX_SESSION);
    info.extend_from_slice(transcript);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).expect("HKDF-SHA384 32B expand cannot fail");
    // SAS = SHA-384(key || transcript)[..16].
    let mut h = Sha384::new();
    h.update(key);
    h.update(transcript);
    let d = h.finalize();
    let mut sas = [0u8; SAS_LEN];
    sas.copy_from_slice(&d[..SAS_LEN]);
    (key, sas)
}

/// Responder side: decapsulate initiator bundle, verify sigs, derive.
/// `responder_keys` is the bundle published earlier. Single round trip
/// suffices for PSK-only legs; signature legs use the two-phase flow
/// below (`transcript` is computable by both sides after bundle exchange,
/// then each side signs it — see tests).
pub fn responder_complete(
    responder_keys: &EphemeralKeys,
    initiator_bundle: &[u8],
    auth: &AuthMaterial<'_>,
) -> Result<KexSession, CoreError> {
    if initiator_bundle.len() != INITIATOR_BUNDLE_LEN {
        return Err(CoreError::Malformed);
    }
    let mut rb = Vec::with_capacity(RESPONDER_BUNDLE_LEN);
    rb.extend_from_slice(&responder_keys.x_public);
    rb.extend_from_slice(&responder_keys.ml_ek);
    let t = transcript(&rb, initiator_bundle)?;
    // Verify-before-derive: sig legs (if any) BEFORE decaps-derived use.
    let psk: Option<&[u8; 32]> = match auth {
        AuthMaterial::Psk(p) => Some(*p),
        AuthMaterial::Signatures { responder_vk, responder_sig, initiator_vk, initiator_sig } => {
            verify_sig_legs(&t, responder_vk, responder_sig, initiator_vk, initiator_sig)?;
            None
        }
        AuthMaterial::Both { psk, responder_vk, responder_sig, initiator_vk, initiator_sig } => {
            verify_sig_legs(&t, responder_vk, responder_sig, initiator_vk, initiator_sig)?;
            Some(*psk)
        }
    };
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&initiator_bundle[..32]);
    let hybrid: Zeroizing<[u8; HYBRID_SS]> = responder_keys
        .decapsulate(&eph, &initiator_bundle[32..])
        .map_err(|_| CoreError::Malformed)?;
    let (session_key, sas) = derive(&t, &hybrid, psk);
    Ok(KexSession { session_key, transcript: t, sas })
}

/// Initiator phase 1: encapsulate to the responder bundle.
/// Returns `(initiator_bundle, hybrid_secret)`. The hybrid secret stays in
/// a zeroizing container; phase 2 consumes it. No authentication happens
/// here — signatures can only exist AFTER both bundles are known (they
/// cover the transcript), so sig verification lives in phase 2.
pub fn initiator_begin(
    responder_bundle: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; HYBRID_SS]>), CoreError> {
    if responder_bundle.len() != RESPONDER_BUNDLE_LEN {
        return Err(CoreError::Malformed);
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&responder_bundle[..32]);
    let (ml_ct, hybrid, eph_pub) =
        EphemeralKeys::encapsulate(&x, &responder_bundle[32..]).map_err(|_| CoreError::Malformed)?;
    let mut ib = Vec::with_capacity(INITIATOR_BUNDLE_LEN);
    ib.extend_from_slice(&eph_pub);
    ib.extend_from_slice(&ml_ct);
    Ok((ib, hybrid))
}

/// Initiator phase 2: transcript, verify-before-derive, derive.
/// `hybrid` MUST be the phase-1 output for these exact bundles (caller
/// discipline; mismatched inputs yield mismatched keys, never oracles).
pub fn initiator_finish(
    responder_bundle: &[u8],
    initiator_bundle: &[u8],
    hybrid: &[u8; HYBRID_SS],
    auth: &AuthMaterial<'_>,
) -> Result<KexSession, CoreError> {
    let t = transcript(responder_bundle, initiator_bundle)?;
    let psk: Option<&[u8; 32]> = match auth {
        AuthMaterial::Psk(p) => Some(*p),
        AuthMaterial::Signatures { responder_vk, responder_sig, initiator_vk, initiator_sig } => {
            verify_sig_legs(&t, responder_vk, responder_sig, initiator_vk, initiator_sig)?;
            None
        }
        AuthMaterial::Both { psk, responder_vk, responder_sig, initiator_vk, initiator_sig } => {
            verify_sig_legs(&t, responder_vk, responder_sig, initiator_vk, initiator_sig)?;
            Some(*psk)
        }
    };
    let (session_key, sas) = derive(&t, hybrid, psk);
    Ok(KexSession { session_key, transcript: t, sas })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Mldsa87SigningKey;

    fn psk() -> [u8; 32] {
        [0x77u8; 32]
    }

    #[test]
    fn psk_session_agrees_and_binds_transcript() {
        let resp_keys = EphemeralKeys::generate().unwrap();
        let mut rb = Vec::new();
        rb.extend_from_slice(&resp_keys.x_public);
        rb.extend_from_slice(&resp_keys.ml_ek);
        let p = psk();
        // Phase 1: encaps. Phase 2: transcript + derive (PSK leg).
        let (ib, hybrid) = initiator_begin(&rb).unwrap();
        let init_sess = initiator_finish(&rb, &ib, &hybrid, &AuthMaterial::Psk(&p)).unwrap();
        let resp_sess = responder_complete(&resp_keys, &ib, &AuthMaterial::Psk(&p)).unwrap();
        assert_eq!(init_sess.session_key(), resp_sess.session_key());
        assert_eq!(init_sess.sas_string(), resp_sess.sas_string());
        // 16-byte SAS as hex pairs: 32 chars + 7 dashes = 39.
        assert_eq!(init_sess.sas_string().len(), 39);
        assert_eq!(init_sess.transcript(), resp_sess.transcript());
        // Different PSK => different key (authentication binds).
        let mut p2 = p;
        p2[0] ^= 1;
        let other = initiator_finish(&rb, &ib, &hybrid, &AuthMaterial::Psk(&p2)).unwrap();
        assert_ne!(init_sess.session_key(), other.session_key());
    }

    #[test]
    fn sig_legs_verify_before_derive() {
        let resp_keys = EphemeralKeys::generate().unwrap();
        let mut rb = Vec::new();
        rb.extend_from_slice(&resp_keys.x_public);
        rb.extend_from_slice(&resp_keys.ml_ek);
        let (sk_r, vk_r) = Mldsa87SigningKey::generate().unwrap();
        let (sk_i, vk_i) = Mldsa87SigningKey::generate().unwrap();
        // Real two-phase flow: bundles first, THEN both sides sign the
        // transcript (sigs cannot exist before ib is known).
        let (ib, hybrid) = initiator_begin(&rb).unwrap();
        let t = transcript(&rb, &ib).unwrap();
        let sr = sk_r.sign(crate::policy::DOMAIN_SIG_RESPONDER, &t);
        let si = sk_i.sign(crate::policy::DOMAIN_SIG_INITIATOR, &t);
        let legs = AuthMaterial::Signatures {
            responder_vk: &vk_r, responder_sig: &sr,
            initiator_vk: &vk_i, initiator_sig: &si,
        };
        // Full SIG-only sessions agree.
        let s_init = initiator_finish(&rb, &ib, &hybrid, &legs).unwrap();
        let s_resp = responder_complete(
            &resp_keys,
            &ib,
            &AuthMaterial::Signatures { responder_vk: &vk_r, responder_sig: &sr, initiator_vk: &vk_i, initiator_sig: &si },
        )
        .unwrap();
        assert_eq!(s_init.session_key(), s_resp.session_key());
        // Forged sig fails BEFORE any key is returned.
        let mut bad = sr.clone();
        bad[0] ^= 1;
        assert!(initiator_finish(
            &rb, &ib, &hybrid,
            &AuthMaterial::Signatures { responder_vk: &vk_r, responder_sig: &bad, initiator_vk: &vk_i, initiator_sig: &si },
        )
        .is_err());
        // Malformed bundles fail closed.
        let p = psk();
        assert!(initiator_begin(&[0u8; 10]).is_err());
        assert!(responder_complete(&resp_keys, &[0u8; 10], &AuthMaterial::Psk(&p)).is_err());
    }
}
