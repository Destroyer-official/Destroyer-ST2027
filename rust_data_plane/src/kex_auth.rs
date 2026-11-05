//! Authenticated hybrid KEX session (Rust secure core).
//!
//! Wire-identical bundle layout to the existing data-plane KEX
//! (`main.rs` kex-listen/connect) and the Python reference
//! (`noise_pq.py` transcript discipline, `secure_transmit_2027.py`
//! verify-before-derive):
//!
//! ```text
//! responder_bundle = p384_pub(97) || ml_ek(1568)   (1665 bytes)
//! initiator_bundle = eph_p384_pub(97) || ml_ct(1568) (1665 bytes)
//! transcript       = SHA-384(responder_bundle || initiator_bundle)
//! hybrid_ss        = ml_ss(32) || p384_ss(48)      (80 bytes)
//! auth_binding     = SHA-384(DOMAIN_AUTH_BINDING || transcript || len(sig_R) || sig_R || len(sig_I) || sig_I)
//! session_key      = HKDF-SHA384(hybrid_ss, salt=PSK?, info=DOMAIN_KEX_SESSION || auth_binding)
//! ```
//!
//! # Threat Model & Production Discipline
//!
//! ## Lab-Only Feature: PSK-Only Key Exchange
//! Current Behavior in `--lab`: Allows two endpoints to establish a session using
//! only a shared 32-byte pre-shared key (PSK) and ephemeral hybrid KEM (SecP384r1MLKEM1024),
//! without signing the handshake transcript with identity private keys.
//!
//! ## Primary Security Gap: Identity Binding & Compromise Blast Radius
//! Symmetric pre-shared keys do NOT provide individual identity binding, non-repudiation,
//! or resistance to internal network pivoting. If a single endpoint in a tactical enclave
//! is physically or logically compromised, an adversary extracting the PSK can impersonate
//! ANY node in the network and execute active Unknown-Key-Share (UKS) or Man-in-the-Middle
//! (MITM) attacks against all peers.
//!
//! ## Production Mechanism: Mandatory Mutual ML-DSA-87 Signatures Bound into KDF
//! Outside explicit `--lab` mode (`P2P_LAB_MODE=1` or `ST2027_LAB_MODE=1`), production
//! strictly enforces mandatory mutual ML-DSA-87 public key authentication pinned via
//! `--auth-sk-file` and `--peer-auth-pk-file`. Any attempt to establish a session with
//! PSK-only authentication (`AuthMaterial::Psk`) is rejected fail-closed with
//! `CoreError::AuthRequired`.
//!
//! Furthermore, following 2026/2027 post-quantum protocol standards (RFC 10024; FIPS 203;
//! FIPS 204; Fiedler/Guenther PKC 2025; Bhargavan USENIX 2024; Giacon-Heuer-Poettering PKC 2018):
//! 1. **Verify-Before-Derive:** Mutual ML-DSA-87 signatures MUST verify against pinned
//!    peer identity keys BEFORE any key material or decapsulation secret is derived.
//! 2. **KDF Transcript Signature Binding:** The verified signatures are explicitly bound
//!    into the KDF transcript via `auth_binding`. Stripping, altering, or substituting
//!    a signature or public key mathematically alters the derived session key, confirmation
//!    tags, and SAS fingerprint.
//! 3. **Mutual Key Confirmation:** Both sides derive role-separated confirmation tags
//!    to guarantee mutual knowledge of the negotiated session key before application data flows.

use hkdf::Hkdf;
use sha2::{Digest, Sha384};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::auth::{verify_initiator, verify_responder, Mldsa87VerifyingKey};
use crate::kem::{EphemeralKeys, HYBRID_SS};
use crate::policy::{
    CoreError, DOMAIN_AUTH_BINDING, DOMAIN_CONFIRM_INITIATOR, DOMAIN_CONFIRM_RESPONDER,
    DOMAIN_KEX_SESSION, MLKEM1024_CT, MLKEM1024_PK, P384_PK, SAS_LEN, TRANSCRIPT_LEN,
};

/// Bundle: responder `p384_pub || ml_ek`. Fixed 1665 bytes.
pub const RESPONDER_BUNDLE_LEN: usize = P384_PK + MLKEM1024_PK;
/// Bundle: initiator `eph_p384_pub || ml_ct`. Fixed 1665 bytes.
pub const INITIATOR_BUNDLE_LEN: usize = P384_PK + MLKEM1024_CT;
/// Confirmation tag size (32 bytes).
pub const CONFIRMATION_TAG_LEN: usize = 32;

/// Role indicator for key confirmation exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexRole {
    Responder,
    Initiator,
}

/// Check if the runtime environment allows lab-only surfaces.
/// Returns false if `P2P_PRODUCTION=1` is asserted or if neither `P2P_LAB_MODE`
/// nor `ST2027_LAB_MODE` is set to "1".
pub fn is_lab_mode() -> bool {
    if std::env::var("P2P_PRODUCTION").as_deref() == Ok("1") {
        return false;
    }
    std::env::var("P2P_LAB_MODE").as_deref() == Ok("1")
        || std::env::var("ST2027_LAB_MODE").as_deref() == Ok("1")
}

/// Authenticated auth material.
///
/// In production, mutual ML-DSA-87 signatures (`Signatures` or `Both`) are MANDATORY.
/// `Psk` is a lab-only fallback and is strictly refused in production mode.
pub enum AuthMaterial<'a> {
    /// 32-byte pre-shared key.
    /// LAB-ONLY: Refused outside explicit lab mode (`P2P_LAB_MODE=1` or `ST2027_LAB_MODE=1`).
    Psk(&'a [u8; 32]),
    /// Mutual ML-DSA-87 transcript-signature legs (both directions verified).
    Signatures {
        responder_vk: &'a Mldsa87VerifyingKey,
        responder_sig: &'a [u8],
        initiator_vk: &'a Mldsa87VerifyingKey,
        initiator_sig: &'a [u8],
    },
    /// PSK plus both ML-DSA-87 legs (highest assurance, CNSA 2.0 production standard).
    Both {
        psk: &'a [u8; 32],
        responder_vk: &'a Mldsa87VerifyingKey,
        responder_sig: &'a [u8],
        initiator_vk: &'a Mldsa87VerifyingKey,
        initiator_sig: &'a [u8],
    },
}

impl<'a> AuthMaterial<'a> {
    /// True if mutual ML-DSA-87 identity signatures are provided.
    pub fn has_signatures(&self) -> bool {
        matches!(
            self,
            AuthMaterial::Signatures { .. } | AuthMaterial::Both { .. }
        )
    }

    /// Access the pre-shared key if provided.
    pub fn psk(&self) -> Option<&'a [u8; 32]> {
        match self {
            AuthMaterial::Psk(p) => Some(*p),
            AuthMaterial::Signatures { .. } => None,
            AuthMaterial::Both { psk, .. } => Some(*psk),
        }
    }
}

/// Established session: 32-byte frame key (zeroized on drop), raw & bound transcripts, SAS.
#[derive(ZeroizeOnDrop)]
pub struct KexSession {
    session_key: [u8; 32],
    raw_transcript: [u8; TRANSCRIPT_LEN],
    transcript: [u8; TRANSCRIPT_LEN],
    sas: [u8; SAS_LEN],
}

impl KexSession {
    /// Borrow the session key for a single copy-out (e.g. into `FrameKey`).
    pub fn session_key(&self) -> &[u8; 32] {
        &self.session_key
    }
    /// Transcript hash fed to KDF (cryptographically bound to signatures when present).
    pub fn transcript(&self) -> &[u8; TRANSCRIPT_LEN] {
        &self.transcript
    }
    /// Raw unauthenticated bundle transcript hash: SHA-384(responder_bundle || initiator_bundle).
    pub fn raw_transcript(&self) -> &[u8; TRANSCRIPT_LEN] {
        &self.raw_transcript
    }
    /// SAS bytes (compare out-of-band; never auto-trust).
    pub fn sas(&self) -> &[u8; SAS_LEN] {
        &self.sas
    }
    /// SAS as `XXXX-XXXX-XXXX-XXXX` hex (constant-length, no secret branch).
    pub fn sas_string(&self) -> String {
        const H: &[u8; 16] = b"0123456789ABCDEF";
        let mut s = String::with_capacity(39);
        for (i, b) in self.sas.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                s.push('-');
            }
            s.push(H[(b >> 4) as usize] as char);
            s.push(H[(b & 15) as usize] as char);
        }
        s
    }

    /// Compute 32-byte responder key confirmation tag:
    /// HKDF-SHA384(session_key, DOMAIN_CONFIRM_RESPONDER || transcript)[..32]
    pub fn responder_confirmation_tag(&self) -> [u8; CONFIRMATION_TAG_LEN] {
        compute_tag(
            &self.session_key,
            DOMAIN_CONFIRM_RESPONDER,
            &self.transcript,
        )
    }

    /// Compute 32-byte initiator key confirmation tag:
    /// HKDF-SHA384(session_key, DOMAIN_CONFIRM_INITIATOR || transcript)[..32]
    pub fn initiator_confirmation_tag(&self) -> [u8; CONFIRMATION_TAG_LEN] {
        compute_tag(
            &self.session_key,
            DOMAIN_CONFIRM_INITIATOR,
            &self.transcript,
        )
    }

    /// Verify peer key confirmation tag in constant time.
    pub fn verify_peer_tag(
        &self,
        peer_tag: &[u8; CONFIRMATION_TAG_LEN],
        peer_role: KexRole,
    ) -> Result<(), CoreError> {
        let expected = match peer_role {
            KexRole::Responder => self.responder_confirmation_tag(),
            KexRole::Initiator => self.initiator_confirmation_tag(),
        };
        if crate::ct::ct_eq(&expected, peer_tag) {
            Ok(())
        } else {
            Err(CoreError::BadSignature)
        }
    }
}

/// Compute 32-byte key confirmation tag via HKDF-SHA384.
fn compute_tag(
    session_key: &[u8; 32],
    label: &[u8],
    transcript_binding: &[u8; TRANSCRIPT_LEN],
) -> [u8; CONFIRMATION_TAG_LEN] {
    let hk = Hkdf::<Sha384>::new(Some(session_key), label);
    let mut tag = [0u8; CONFIRMATION_TAG_LEN];
    hk.expand(transcript_binding, &mut tag)
        .expect("confirmation tag expand cannot fail");
    tag
}

/// Raw transcript = SHA-384(responder_bundle || initiator_bundle).
pub fn transcript(
    responder_bundle: &[u8],
    initiator_bundle: &[u8],
) -> Result<[u8; TRANSCRIPT_LEN], CoreError> {
    if responder_bundle.len() != RESPONDER_BUNDLE_LEN
        || initiator_bundle.len() != INITIATOR_BUNDLE_LEN
    {
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

/// Final handshake binding = SHA-384(DOMAIN_AUTH_BINDING || transcript || len(resp_sig) || resp_sig || len(init_sig) || init_sig).
/// Signatures are length-prefixed so the encoding is unambiguous.
/// Binding is fed to the KDF so stripping, replacing, or substituting a signature changes
/// the derived session key, confirmation tags, and SAS fingerprint.
pub fn auth_binding(
    transcript_hash: &[u8; TRANSCRIPT_LEN],
    responder_sig: &[u8],
    initiator_sig: &[u8],
) -> [u8; TRANSCRIPT_LEN] {
    let mut h = Sha384::new();
    h.update(DOMAIN_AUTH_BINDING);
    h.update(transcript_hash);
    h.update((responder_sig.len() as u32).to_be_bytes());
    h.update(responder_sig);
    h.update((initiator_sig.len() as u32).to_be_bytes());
    h.update(initiator_sig);
    let d = h.finalize();
    let mut out = [0u8; TRANSCRIPT_LEN];
    out.copy_from_slice(&d);
    out
}

/// Verify-before-derive: both ML-DSA transcript signatures MUST verify
/// before ANY key material is derived or returned. Returns `BadSignature` on failure.
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
fn derive(
    bound_transcript: &[u8; TRANSCRIPT_LEN],
    hybrid_ss: &[u8; HYBRID_SS],
    psk: Option<&[u8; 32]>,
) -> ([u8; 32], [u8; SAS_LEN]) {
    let salt: &[u8] = match psk {
        Some(p) => &p[..],
        None => DOMAIN_KEX_SESSION,
    };
    let hk = Hkdf::<Sha384>::new(Some(salt), hybrid_ss);
    let mut info = Vec::with_capacity(DOMAIN_KEX_SESSION.len() + TRANSCRIPT_LEN);
    info.extend_from_slice(DOMAIN_KEX_SESSION);
    info.extend_from_slice(bound_transcript);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .expect("HKDF-SHA384 32B expand cannot fail");
    // SAS = SHA-384(key || bound_transcript)[..16].
    let mut h = Sha384::new();
    h.update(key);
    h.update(bound_transcript);
    let d = h.finalize();
    let mut sas = [0u8; SAS_LEN];
    sas.copy_from_slice(&d[..SAS_LEN]);
    (key, sas)
}

/// Responder side: decapsulate initiator bundle, verify sigs, derive.
/// Evaluates environment via `is_lab_mode()` to enforce production discipline.
pub fn responder_complete(
    responder_keys: &EphemeralKeys,
    initiator_bundle: &[u8],
    auth: &AuthMaterial<'_>,
) -> Result<KexSession, CoreError> {
    responder_complete_policy(responder_keys, initiator_bundle, auth, is_lab_mode())
}

/// Responder side with explicit policy control (lab vs production).
/// Outside lab mode, `AuthMaterial::Psk` is strictly rejected with `CoreError::AuthRequired`.
pub fn responder_complete_policy(
    responder_keys: &EphemeralKeys,
    initiator_bundle: &[u8],
    auth: &AuthMaterial<'_>,
    lab_mode: bool,
) -> Result<KexSession, CoreError> {
    if initiator_bundle.len() != INITIATOR_BUNDLE_LEN {
        return Err(CoreError::Malformed);
    }
    let mut rb = Vec::with_capacity(RESPONDER_BUNDLE_LEN);
    rb.extend_from_slice(&responder_keys.p_public);
    rb.extend_from_slice(&responder_keys.ml_ek);
    let raw_t = transcript(&rb, initiator_bundle)?;

    // Policy gate: PSK-only is strictly forbidden in production.
    let (bound_t, psk) = match auth {
        AuthMaterial::Psk(p) => {
            if !lab_mode {
                return Err(CoreError::AuthRequired);
            }
            (raw_t, Some(*p))
        }
        AuthMaterial::Signatures {
            responder_vk,
            responder_sig,
            initiator_vk,
            initiator_sig,
        } => {
            // Verify-before-derive: mutual signatures MUST verify before decaps or derivation
            verify_sig_legs(
                &raw_t,
                responder_vk,
                responder_sig,
                initiator_vk,
                initiator_sig,
            )?;
            let bound = auth_binding(&raw_t, responder_sig, initiator_sig);
            (bound, None)
        }
        AuthMaterial::Both {
            psk,
            responder_vk,
            responder_sig,
            initiator_vk,
            initiator_sig,
        } => {
            // Verify-before-derive: mutual signatures MUST verify before decaps or derivation
            verify_sig_legs(
                &raw_t,
                responder_vk,
                responder_sig,
                initiator_vk,
                initiator_sig,
            )?;
            let bound = auth_binding(&raw_t, responder_sig, initiator_sig);
            (bound, Some(*psk))
        }
    };

    let mut eph = [0u8; P384_PK];
    eph.copy_from_slice(&initiator_bundle[..P384_PK]);
    let hybrid: Zeroizing<[u8; HYBRID_SS]> = responder_keys
        .decapsulate(&eph, &initiator_bundle[P384_PK..])
        .map_err(|_| CoreError::Malformed)?;
    let (session_key, sas) = derive(&bound_t, &hybrid, psk);
    Ok(KexSession {
        session_key,
        raw_transcript: raw_t,
        transcript: bound_t,
        sas,
    })
}

/// Initiator phase 1: encapsulate to the responder bundle.
/// Returns `(initiator_bundle, hybrid_secret)`. The hybrid secret stays in
/// a zeroizing container; phase 2 consumes it.
pub fn initiator_begin(
    responder_bundle: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; HYBRID_SS]>), CoreError> {
    if responder_bundle.len() != RESPONDER_BUNDLE_LEN {
        return Err(CoreError::Malformed);
    }
    let mut p = [0u8; P384_PK];
    p.copy_from_slice(&responder_bundle[..P384_PK]);
    let (ml_ct, hybrid, eph_pub) = EphemeralKeys::encapsulate(&p, &responder_bundle[P384_PK..])
        .map_err(|_| CoreError::Malformed)?;
    let mut ib = Vec::with_capacity(INITIATOR_BUNDLE_LEN);
    ib.extend_from_slice(&eph_pub);
    ib.extend_from_slice(&ml_ct);
    Ok((ib, hybrid))
}

/// Initiator phase 2: transcript, verify-before-derive, derive.
/// Evaluates environment via `is_lab_mode()` to enforce production discipline.
pub fn initiator_finish(
    responder_bundle: &[u8],
    initiator_bundle: &[u8],
    hybrid: &[u8; HYBRID_SS],
    auth: &AuthMaterial<'_>,
) -> Result<KexSession, CoreError> {
    initiator_finish_policy(
        responder_bundle,
        initiator_bundle,
        hybrid,
        auth,
        is_lab_mode(),
    )
}

/// Initiator phase 2 with explicit policy control (lab vs production).
/// Outside lab mode, `AuthMaterial::Psk` is strictly rejected with `CoreError::AuthRequired`.
pub fn initiator_finish_policy(
    responder_bundle: &[u8],
    initiator_bundle: &[u8],
    hybrid: &[u8; HYBRID_SS],
    auth: &AuthMaterial<'_>,
    lab_mode: bool,
) -> Result<KexSession, CoreError> {
    let raw_t = transcript(responder_bundle, initiator_bundle)?;

    // Policy gate: PSK-only is strictly forbidden in production.
    let (bound_t, psk) = match auth {
        AuthMaterial::Psk(p) => {
            if !lab_mode {
                return Err(CoreError::AuthRequired);
            }
            (raw_t, Some(*p))
        }
        AuthMaterial::Signatures {
            responder_vk,
            responder_sig,
            initiator_vk,
            initiator_sig,
        } => {
            // Verify-before-derive
            verify_sig_legs(
                &raw_t,
                responder_vk,
                responder_sig,
                initiator_vk,
                initiator_sig,
            )?;
            let bound = auth_binding(&raw_t, responder_sig, initiator_sig);
            (bound, None)
        }
        AuthMaterial::Both {
            psk,
            responder_vk,
            responder_sig,
            initiator_vk,
            initiator_sig,
        } => {
            // Verify-before-derive
            verify_sig_legs(
                &raw_t,
                responder_vk,
                responder_sig,
                initiator_vk,
                initiator_sig,
            )?;
            let bound = auth_binding(&raw_t, responder_sig, initiator_sig);
            (bound, Some(*psk))
        }
    };

    let (session_key, sas) = derive(&bound_t, hybrid, psk);
    Ok(KexSession {
        session_key,
        raw_transcript: raw_t,
        transcript: bound_t,
        sas,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Mldsa87SigningKey;
    use crate::policy::{DOMAIN_SIG_INITIATOR, DOMAIN_SIG_RESPONDER};

    fn psk() -> [u8; 32] {
        [0x77u8; 32]
    }

    #[test]
    fn production_mode_strictly_refuses_psk_only_kex() {
        let resp_keys = EphemeralKeys::generate().unwrap();
        let mut rb = Vec::new();
        rb.extend_from_slice(&resp_keys.p_public);
        rb.extend_from_slice(&resp_keys.ml_ek);
        let p = psk();
        let (ib, hybrid) = initiator_begin(&rb).unwrap();

        // In production mode (lab_mode = false), PSK-only MUST fail closed immediately:
        // No identity binding; shared-key compromise risks full impersonation.
        let init_res = initiator_finish_policy(&rb, &ib, &hybrid, &AuthMaterial::Psk(&p), false);
        assert_eq!(init_res.err(), Some(CoreError::AuthRequired));

        let resp_res = responder_complete_policy(&resp_keys, &ib, &AuthMaterial::Psk(&p), false);
        assert_eq!(resp_res.err(), Some(CoreError::AuthRequired));
    }

    #[test]
    fn lab_mode_permits_psk_only_kex_fallback() {
        let resp_keys = EphemeralKeys::generate().unwrap();
        let mut rb = Vec::new();
        rb.extend_from_slice(&resp_keys.p_public);
        rb.extend_from_slice(&resp_keys.ml_ek);
        let p = psk();
        let (ib, hybrid) = initiator_begin(&rb).unwrap();

        // In lab mode (lab_mode = true), PSK-only is permitted for lab test/diagnostic exercises:
        let init_sess =
            initiator_finish_policy(&rb, &ib, &hybrid, &AuthMaterial::Psk(&p), true).unwrap();
        let resp_sess =
            responder_complete_policy(&resp_keys, &ib, &AuthMaterial::Psk(&p), true).unwrap();

        assert_eq!(init_sess.session_key(), resp_sess.session_key());
        assert_eq!(init_sess.sas_string(), resp_sess.sas_string());
        assert_eq!(init_sess.sas_string().len(), 39);
        assert_eq!(init_sess.transcript(), resp_sess.transcript());

        // Different PSK => different key (authentication binds).
        let mut p2 = p;
        p2[0] ^= 1;
        let other =
            initiator_finish_policy(&rb, &ib, &hybrid, &AuthMaterial::Psk(&p2), true).unwrap();
        assert_ne!(init_sess.session_key(), other.session_key());
    }

    #[test]
    fn production_mutual_mldsa87_signatures_bound_into_kdf_transcript() {
        let resp_keys = EphemeralKeys::generate().unwrap();
        let mut rb = Vec::new();
        rb.extend_from_slice(&resp_keys.p_public);
        rb.extend_from_slice(&resp_keys.ml_ek);
        let (sk_r, vk_r) = Mldsa87SigningKey::generate().unwrap();
        let (sk_i, vk_i) = Mldsa87SigningKey::generate().unwrap();

        let (ib, hybrid) = initiator_begin(&rb).unwrap();
        let raw_t = transcript(&rb, &ib).unwrap();
        let sr = sk_r.sign(DOMAIN_SIG_RESPONDER, &raw_t);
        let si = sk_i.sign(DOMAIN_SIG_INITIATOR, &raw_t);

        let legs = AuthMaterial::Signatures {
            responder_vk: &vk_r,
            responder_sig: &sr,
            initiator_vk: &vk_i,
            initiator_sig: &si,
        };

        // Production mode (lab_mode = false) succeeds with mutual ML-DSA-87 signatures:
        let s_init = initiator_finish_policy(&rb, &ib, &hybrid, &legs, false).unwrap();
        let s_resp = responder_complete_policy(&resp_keys, &ib, &legs, false).unwrap();

        // Sessions agree on session key, SAS, and bound transcript:
        assert_eq!(s_init.session_key(), s_resp.session_key());
        assert_eq!(s_init.sas_string(), s_resp.sas_string());
        assert_eq!(s_init.transcript(), s_resp.transcript());

        // CRUCIAL: Verify that transcript() returns the auth-bound transcript, NOT the raw transcript!
        let expected_binding = auth_binding(&raw_t, &sr, &si);
        assert_eq!(s_init.transcript(), &expected_binding);
        assert_ne!(s_init.transcript(), s_init.raw_transcript());
        assert_eq!(s_init.raw_transcript(), &raw_t);

        // Key confirmation tags mutually verify:
        let resp_tag = s_resp.responder_confirmation_tag();
        let init_tag = s_init.initiator_confirmation_tag();
        assert!(s_init
            .verify_peer_tag(&resp_tag, KexRole::Responder)
            .is_ok());
        assert!(s_resp
            .verify_peer_tag(&init_tag, KexRole::Initiator)
            .is_ok());

        // Wrong role tag fails verification:
        assert!(s_init
            .verify_peer_tag(&init_tag, KexRole::Responder)
            .is_err());
    }

    #[test]
    fn highest_assurance_both_mode_psk_and_mutual_mldsa87() {
        let resp_keys = EphemeralKeys::generate().unwrap();
        let mut rb = Vec::new();
        rb.extend_from_slice(&resp_keys.p_public);
        rb.extend_from_slice(&resp_keys.ml_ek);
        let (sk_r, vk_r) = Mldsa87SigningKey::generate().unwrap();
        let (sk_i, vk_i) = Mldsa87SigningKey::generate().unwrap();
        let p = psk();

        let (ib, hybrid) = initiator_begin(&rb).unwrap();
        let raw_t = transcript(&rb, &ib).unwrap();
        let sr = sk_r.sign(DOMAIN_SIG_RESPONDER, &raw_t);
        let si = sk_i.sign(DOMAIN_SIG_INITIATOR, &raw_t);

        let both_auth = AuthMaterial::Both {
            psk: &p,
            responder_vk: &vk_r,
            responder_sig: &sr,
            initiator_vk: &vk_i,
            initiator_sig: &si,
        };

        let s_init = initiator_finish_policy(&rb, &ib, &hybrid, &both_auth, false).unwrap();
        let s_resp = responder_complete_policy(&resp_keys, &ib, &both_auth, false).unwrap();

        assert_eq!(s_init.session_key(), s_resp.session_key());
        assert_eq!(s_init.sas_string(), s_resp.sas_string());

        // Key is salted with PSK: same signatures with different PSK yields divergent session key:
        let mut p2 = p;
        p2[0] ^= 1;
        let both_auth2 = AuthMaterial::Both {
            psk: &p2,
            responder_vk: &vk_r,
            responder_sig: &sr,
            initiator_vk: &vk_i,
            initiator_sig: &si,
        };
        let s_other = initiator_finish_policy(&rb, &ib, &hybrid, &both_auth2, false).unwrap();
        assert_ne!(s_init.session_key(), s_other.session_key());
        assert_ne!(s_init.sas_string(), s_other.sas_string());
    }

    #[test]
    fn signature_tampering_or_forgery_fails_verify_before_derive() {
        let resp_keys = EphemeralKeys::generate().unwrap();
        let mut rb = Vec::new();
        rb.extend_from_slice(&resp_keys.p_public);
        rb.extend_from_slice(&resp_keys.ml_ek);
        let (sk_r, vk_r) = Mldsa87SigningKey::generate().unwrap();
        let (sk_i, vk_i) = Mldsa87SigningKey::generate().unwrap();

        let (ib, hybrid) = initiator_begin(&rb).unwrap();
        let raw_t = transcript(&rb, &ib).unwrap();
        let sr = sk_r.sign(DOMAIN_SIG_RESPONDER, &raw_t);
        let si = sk_i.sign(DOMAIN_SIG_INITIATOR, &raw_t);

        // Tampered responder signature:
        let mut bad_sr = sr.clone();
        bad_sr[0] ^= 1;
        let bad_auth_r = AuthMaterial::Signatures {
            responder_vk: &vk_r,
            responder_sig: &bad_sr,
            initiator_vk: &vk_i,
            initiator_sig: &si,
        };
        assert_eq!(
            initiator_finish_policy(&rb, &ib, &hybrid, &bad_auth_r, false).err(),
            Some(CoreError::BadSignature)
        );

        // Tampered initiator signature:
        let mut bad_si = si.clone();
        bad_si[0] ^= 1;
        let bad_auth_i = AuthMaterial::Signatures {
            responder_vk: &vk_r,
            responder_sig: &sr,
            initiator_vk: &vk_i,
            initiator_sig: &bad_si,
        };
        assert_eq!(
            responder_complete_policy(&resp_keys, &ib, &bad_auth_i, false).err(),
            Some(CoreError::BadSignature)
        );

        // Unknown-Key-Share / Key-substitution attempt (signed by untrusted key):
        let (sk_untrusted, _vk_untrusted) = Mldsa87SigningKey::generate().unwrap();
        let forged_si = sk_untrusted.sign(DOMAIN_SIG_INITIATOR, &raw_t);
        let uks_auth = AuthMaterial::Signatures {
            responder_vk: &vk_r,
            responder_sig: &sr,
            initiator_vk: &vk_i, // Pinned honest key
            initiator_sig: &forged_si,
        };
        assert_eq!(
            responder_complete_policy(&resp_keys, &ib, &uks_auth, false).err(),
            Some(CoreError::BadSignature)
        );
    }

    #[test]
    fn malformed_bundles_fail_closed() {
        let resp_keys = EphemeralKeys::generate().unwrap();
        let p = psk();
        assert_eq!(
            initiator_begin(&[0u8; 10]).err(),
            Some(CoreError::Malformed)
        );
        assert_eq!(
            responder_complete_policy(&resp_keys, &[0u8; 10], &AuthMaterial::Psk(&p), true).err(),
            Some(CoreError::Malformed)
        );
    }
}
