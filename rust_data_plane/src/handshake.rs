//! Noise_XXhfs handshake in Rust (CNSA L5 production path).
//!
//! Byte-identical protocol to the Python reference `noise_pq.py`
//! (profile `Noise_XXhfs_P384_MLKEM1024_MLDSA87_AES256GCM_SHA384`):
//! P-384 ECDH (`p384` crate) + ML-KEM-1024 (`ml-kem`) hybrid forward
//! secrecy per the `hfs` extension's `e1`/`ekem1` tokens, ML-DSA-87
//! signatures substituting the `es`/`se` tokens (role-separated domains),
//! SHA-384 transcript hash, AES-256-GCM handshake encryption, HKDF-SHA384
//! key schedule, exact message lengths (M1 1665, M2 8916, M3 7251).
//!
//! Message flow (lengths fixed; any deviation aborts fail-closed):
//! ```text
//! M1 I->R: e_pub(97) || ml_ek(1568)
//! M2 R->I: e_pub(97) || ml_ct(1568) || enc(sig_r_pk 2592) || enc(sig_r 4627)
//! M3 I->R: enc(sig_i_pk 2592) || enc(sig_i 4627)
//! Split -> (k_send, k_recv) + transcript hash h (channel binding export)
//! ```
//!
//! divergences from the Python backup (all fail-CLOSED direction):
//! - Identity pinning is MANDATORY: `expected_pin` is required; there is
//!   no `allow_unpinned` / TOFU path in this crate (lab flexibility lives
//!   only in `noise_pq.py`).
//! - Single-use ephemerals are consumed (`Option::take`), not nulled.
//! - Secrets are `ZeroizeOnDrop`; comparisons constant-time.
//!
//! Research grounding:
//! - Noise `hfs` draft (Perrin 2018, unofficial/unstable) token skeleton;
//!   PQNoise (Angel et al., CCS 2022, ePrint 2022/539) generic DH→KEM
//!   recipe + fACCE proof; NoisePQC++ (2026) NIST-compliant hybrid Noise;
//!   PQ WireGuard revisit (Hashimoto et al. 2025/1758) KEM-binding fixes
//!   per Cremers et al. CCS'24 — transcript covers every bundle here.
//! - CFRG draft-irtf-cfrg-hybrid-kems: hybrid safe while EITHER half
//!   holds; key pairs MUST never cross hybrid/non-hybrid uses (fresh
//!   ephemerals per session here); LEAK-BIND-K-PK/CT via transcript hash.
//! - IETF draft-ietf-hpke-pq / MLS PQ ciphersuites (Mar 2026):
//!   MLKEM1024-P384 is the NIST 192-bit hybrid — this profile's KEM leg.
//! - NIST IR 8547: classical ECDH/RSA/ECDSA deprecated by 2030; the P-384
//!   leg here is transition-only inside the hybrid, never standalone.
//!
//! HONESTY: like `noise_pq.py` itself states, the ML-DSA-for-es/se
//! substitution is UNPROVEN (no reduction to PQNoise, which keeps DH/KEM
//! auth). Upstream `p384`/`ml-kem`/`ml-dsa` crates are unaudited
//! (CVE-2026-22705 fixed in ml-dsa ≥0.1.0-rc.3, hint-dup fixed ≥rc.4;
//! floor enforced: locked `ml-dsa 0.1.1` — see `policy.rs`).

use aes_gcm::{
    aead::{Aead, KeyInit, Nonce, Payload},
    Aes256Gcm,
};
use hmac::{Hmac, Mac};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    Ciphertext, EncapsulationKey, MlKem1024,
};
use p384::{ecdh::EphemeralSecret, elliptic_curve::Generate, PublicKey, Sec1Point};
use sha2::{Digest, Sha384};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::auth::{Mldsa87SigningKey, Mldsa87VerifyingKey};
use crate::ct::ct_eq;
use crate::policy::{CoreError, MLDSA87_PK, MLDSA87_SIG, MLKEM1024_CT, MLKEM1024_PK};

/// Profile name (identical bytes to `noise_pq.PROTOCOL_NAME`).
pub const PROTOCOL_NAME: &[u8] = b"Noise_XXhfs_P384_MLKEM1024_MLDSA87_AES256GCM_SHA384";
/// PSK-variant profile name (`noise_pq.PROTOCOL_NAME_PSK2`).
pub const PROTOCOL_NAME_PSK2: &[u8] = b"Noise_XXhfs_psk2_P384_MLKEM1024_MLDSA87_AES256GCM_SHA384";
/// Transcript hash length (SHA-384).
pub const HASHLEN: usize = 48;
/// P-384 uncompressed SEC1 public key (`0x04 || X48 || Y48`).
pub const P384_PUB: usize = 97;
/// P-384 ECDH shared secret (x-coordinate, 48 bytes).
pub const P384_SS: usize = 48;
/// Handshake AEAD tag length.
pub const TAG_LEN: usize = 16;
/// M1 exact length: e_pub + ml_ek.
pub const M1_LEN: usize = P384_PUB + MLKEM1024_PK; // 1665
/// M2 exact length: e_pub + ml_ct + enc(pk) + enc(sig).
pub const M2_LEN: usize =
    P384_PUB + MLKEM1024_CT + (MLDSA87_PK + TAG_LEN) + (MLDSA87_SIG + TAG_LEN); // 8916
/// M3 exact length: enc(pk) + enc(sig).
pub const M3_LEN: usize = (MLDSA87_PK + TAG_LEN) + (MLDSA87_SIG + TAG_LEN); // 7251
/// Responder signature domain (identical to `noise_pq.DOMAIN_SEP_SIG_RESP`).
pub const DOMAIN_SIG_RESP: &[u8] = b"ST2027-Noise-XXhfs-MLDSA87-v1-Responder\x00";
/// Initiator signature domain (identical to `noise_pq.DOMAIN_SEP_SIG_INIT`).
pub const DOMAIN_SIG_INIT: &[u8] = b"ST2027-Noise-XXhfs-MLDSA87-v1-Initiator\x00";
/// Frame-key derivation label (`noise_pq.derive_shared_frame_key`).
pub const LABEL_FRAME_KEY: &[u8] = b"ST2027-Rust-DataPlane-SharedFrameKey";
/// Ratchet-root derivation label (`noise_pq.derive_double_ratchet_root`).
pub const LABEL_RATCHET_ROOT: &[u8] = b"ST2027-DoubleRatchet-RootKey";

/// Split output: `(k1, k2, transcript_h)` — k1 initiator→responder leg.
pub type SplitKeys = ([u8; 32], [u8; 32], [u8; HASHLEN]);

type HmacSha384 = Hmac<Sha384>;

/// Noise-spec HKDF(ck, ikm): temp=HMAC(ck,ikm); out_i=HMAC(temp,prev||i).
/// Mirrors `noise_pq._noise_hkdf` exactly (SHA-384, 1..=3 outputs).
fn noise_hkdf(
    ck: &[u8; HASHLEN],
    ikm: &[u8],
    n_out: usize,
) -> Result<Vec<[u8; HASHLEN]>, CoreError> {
    if !(1..=3).contains(&n_out) {
        return Err(CoreError::Malformed);
    }
    let mut mac = HmacSha384::new_from_slice(ck).map_err(|_| CoreError::Malformed)?;
    mac.update(ikm);
    let temp = mac.finalize().into_bytes();
    let mut outs = Vec::with_capacity(n_out);
    let mut prev = Vec::new();
    for i in 1..=n_out as u8 {
        let mut m = HmacSha384::new_from_slice(&temp).map_err(|_| CoreError::Malformed)?;
        m.update(&prev);
        m.update(&[i]);
        let d = m.finalize().into_bytes();
        let mut o = [0u8; HASHLEN];
        o.copy_from_slice(&d);
        prev = d.to_vec();
        outs.push(o);
    }
    Ok(outs)
}

/// Noise SymmetricState (SHA-384 / AES-256-GCM, spec section 5).
/// Mirrors `noise_pq.SymmetricState` including the ciphertext-absorbing
/// `encrypt_and_hash`/`decrypt_and_hash` order (transcript forks
/// otherwise — caught live in the Python reference).
#[derive(ZeroizeOnDrop)]
struct SymmetricState {
    h: [u8; HASHLEN],
    ck: [u8; HASHLEN],
    key: Option<[u8; 32]>,
    n: u64,
}

impl SymmetricState {
    fn new(protocol_name: &[u8]) -> Self {
        let mut h = [0u8; HASHLEN];
        if protocol_name.len() <= HASHLEN {
            h[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            let d = Sha384::digest(protocol_name);
            h.copy_from_slice(&d);
        }
        Self {
            h,
            ck: h,
            key: None,
            n: 0,
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha384::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h.copy_from_slice(&hasher.finalize());
    }

    fn mix_key(&mut self, ikm: &[u8]) -> Result<(), CoreError> {
        let outs = noise_hkdf(&self.ck, ikm, 2)?;
        self.ck = outs[0];
        let mut k = [0u8; 32];
        k.copy_from_slice(&outs[1][..32]);
        if let Some(ref mut old) = self.key {
            old.zeroize();
        }
        self.key = Some(k);
        self.n = 0;
        Ok(())
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) -> Result<(), CoreError> {
        let outs = noise_hkdf(&self.ck, ikm, 3)?;
        self.ck = outs[0];
        self.mix_hash(&outs[1]);
        let mut k = [0u8; 32];
        k.copy_from_slice(&outs[2][..32]);
        if let Some(ref mut old) = self.key {
            old.zeroize();
        }
        self.key = Some(k);
        self.n = 0;
        Ok(())
    }

    fn nonce(&self) -> Result<Nonce<Aes256Gcm>, CoreError> {
        if self.n == u64::MAX {
            return Err(CoreError::Malformed);
        }
        let mut b = [0u8; 12];
        b[..8].copy_from_slice(&self.n.to_be_bytes());
        Ok(Nonce::<Aes256Gcm>::from(b))
    }

    /// Encrypt-and-MixHash(ciphertext). AAD is the running transcript `h`.
    fn encrypt_and_hash(&mut self, pt: &[u8]) -> Result<Vec<u8>, CoreError> {
        let out = match self.key {
            None => pt.to_vec(),
            Some(k) => {
                let cipher = Aes256Gcm::new_from_slice(&k).map_err(|_| CoreError::Malformed)?;
                let ct = cipher
                    .encrypt(
                        &self.nonce()?,
                        Payload {
                            msg: pt,
                            aad: &self.h,
                        },
                    )
                    .map_err(|_| CoreError::Malformed)?;
                self.n += 1;
                ct
            }
        };
        self.mix_hash(&out);
        Ok(out)
    }

    /// Decrypt-and-MixHash(ciphertext). Tag failure quarantines upstream.
    fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<Vec<u8>, CoreError> {
        let out = match self.key {
            None => ct.to_vec(),
            Some(k) => {
                let cipher = Aes256Gcm::new_from_slice(&k).map_err(|_| CoreError::Malformed)?;
                let pt = cipher
                    .decrypt(
                        &self.nonce()?,
                        Payload {
                            msg: ct,
                            aad: &self.h,
                        },
                    )
                    .map_err(|_| CoreError::BadSignature)?;
                self.n += 1;
                pt
            }
        };
        self.mix_hash(ct);
        Ok(out)
    }

    /// Split: (k1[:32], k2[:32]) = HKDF(ck, "", 2). Returns keys + `h`.
    fn split(&self) -> Result<SplitKeys, CoreError> {
        let outs = noise_hkdf(&self.ck, b"", 2)?;
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&outs[0][..32]);
        k2.copy_from_slice(&outs[1][..32]);
        Ok((k1, k2, self.h))
    }
}

/// P-384 ephemeral keygen → 97-byte uncompressed SEC1 public key.
/// Encoding pinned (`0x04` prefix, exact length) like `_p384_keygen`.
fn p384_keygen() -> Result<(EphemeralSecret, Vec<u8>), CoreError> {
    let sk = EphemeralSecret::generate();
    let enc = Sec1Point::from(sk.public_key());
    let b = enc.as_ref();
    if b.len() != P384_PUB || b[0] != 0x04 {
        return Err(CoreError::Malformed);
    }
    Ok((sk, b.to_vec()))
}

/// P-384 ECDH with SEC1 point validation (mirrors `_p384_dh`).
fn p384_dh(sk: &EphemeralSecret, peer_bytes: &[u8]) -> Result<[u8; P384_SS], CoreError> {
    if peer_bytes.len() != P384_PUB {
        return Err(CoreError::Malformed);
    }
    let peer = PublicKey::from_sec1_bytes(peer_bytes).map_err(|_| CoreError::Malformed)?;
    let ss = sk.diffie_hellman(&peer);
    let raw = ss.raw_secret_bytes();
    if raw.len() != P384_SS {
        return Err(CoreError::Malformed);
    }
    let mut out = [0u8; P384_SS];
    out.copy_from_slice(&raw[..]);
    Ok(out)
}

/// ML-KEM-1024 keygen (sizes pinned, mirrors `_mlkem_keygen`).
fn mlkem_keygen() -> Result<(Vec<u8>, ml_kem::DecapsulationKey<MlKem1024>), CoreError> {
    let (dk, ek) = MlKem1024::generate_keypair();
    let b = ek.to_bytes().to_vec();
    if b.len() != MLKEM1024_PK {
        return Err(CoreError::Malformed);
    }
    Ok((b, dk))
}

/// Split transport keys by role + export transcript (mirrors `split_session`).
fn finish_split(
    sym: &SymmetricState,
    is_initiator: bool,
) -> Result<SplitKeys, CoreError> {
    let (k1, k2, h) = sym.split()?;
    Ok(if is_initiator {
        (k1, k2, h)
    } else {
        (k2, k1, h)
    })
}

/// `derive_shared_frame_key`: HMAC-SHA384(h, k1||k2||LABEL)[:32].
/// Byte-identical to `noise_pq.derive_shared_frame_key`.
pub fn derive_shared_frame_key(
    k_send: &[u8; 32],
    k_recv: &[u8; 32],
    h: &[u8; HASHLEN],
    is_initiator: bool,
) -> [u8; 32] {
    let (k1, k2) = if is_initiator {
        (k_send, k_recv)
    } else {
        (k_recv, k_send)
    };
    let mut m = HmacSha384::new_from_slice(h).expect("HMAC accepts 48B key");
    m.update(k1);
    m.update(k2);
    m.update(LABEL_FRAME_KEY);
    let d = m.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}

/// `derive_double_ratchet_root` → (root_key, transcript_h).
pub fn derive_double_ratchet_root(
    k_send: &[u8; 32],
    k_recv: &[u8; 32],
    h: &[u8; HASHLEN],
    is_initiator: bool,
) -> ([u8; 32], [u8; HASHLEN]) {
    let (k1, k2) = if is_initiator {
        (k_send, k_recv)
    } else {
        (k_recv, k_send)
    };
    let mut m = HmacSha384::new_from_slice(h).expect("HMAC accepts 48B key");
    m.update(k1);
    m.update(k2);
    m.update(LABEL_RATCHET_ROOT);
    let d = m.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    (out, *h)
}

/// Handshake role state machine. Single-use fields are `Option::take`n
/// (never reused); `quarantine()` latches irreversibly like the Python ref.
pub struct Handshake {
    is_initiator: bool,
    sym: SymmetricState,
    e_secret: Option<EphemeralSecret>,
    ml_dk: Option<ml_kem::DecapsulationKey<ml_kem::MlKem1024>>,
    sig_sk: Option<Mldsa87SigningKey>,
    sig_pk: Vec<u8>,
    psk: Option<Zeroizing<[u8; 32]>>,
    peer_sig_pk: Option<Vec<u8>>,
    m3_done: bool,
    split_done: bool,
    quarantined: bool,
}

impl Handshake {
    fn new(
        is_initiator: bool,
        sig_sk: Mldsa87SigningKey,
        sig_pk: Vec<u8>,
        psk: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        if sig_pk.len() != MLDSA87_PK {
            return Err(CoreError::Malformed);
        }
        // Validate the identity key parses (fail-closed on garbage pins).
        Mldsa87VerifyingKey::from_bytes(&sig_pk)?;
        let proto = if psk.is_some() {
            PROTOCOL_NAME_PSK2
        } else {
            PROTOCOL_NAME
        };
        Ok(Self {
            is_initiator,
            sym: SymmetricState::new(proto),
            e_secret: None,
            ml_dk: None,
            sig_sk: Some(sig_sk),
            sig_pk,
            psk: psk.map(Zeroizing::new),
            peer_sig_pk: None,
            m3_done: false,
            split_done: false,
            quarantined: false,
        })
    }

    /// Irreversible latching quarantine (mirrors `NoiseSession.quarantine`).
    fn quarantine(&mut self) {
        self.e_secret = None;
        self.ml_dk = None;
        self.sig_sk = None;
        self.psk = None;
        self.quarantined = true;
    }

    fn check_clean(&self, initiator_only: bool) -> Result<(), CoreError> {
        if self.quarantined || self.split_done {
            return Err(CoreError::Malformed);
        }
        if initiator_only != self.is_initiator {
            return Err(CoreError::Malformed);
        }
        Ok(())
    }

    /// M1: `-> e, e1`. Initiator only, fresh session only.
    pub fn initiator_hello(&mut self) -> Result<Vec<u8>, CoreError> {
        self.check_clean(true)?;
        if self.e_secret.is_some() || self.ml_dk.is_some() {
            return Err(CoreError::Malformed);
        }
        let (e_sk, e_pub) = p384_keygen()?;
        self.e_secret = Some(e_sk);
        self.sym.mix_hash(&e_pub);
        let (ml_ek, ml_dk) = mlkem_keygen()?;
        self.ml_dk = Some(ml_dk);
        self.sym.mix_hash(&ml_ek);
        let mut m1 = Vec::with_capacity(M1_LEN);
        m1.extend_from_slice(&e_pub);
        m1.extend_from_slice(&ml_ek);
        debug_assert_eq!(m1.len(), M1_LEN);
        Ok(m1)
    }

    /// M2: process M1, emit `e_pub || ml_ct || enc(pk) || enc(sig)`.
    /// Consumes our ephemeral ECDH secret immediately after use (SP 800-227
    /// zero-dwell, mirroring the Python reference).
    pub fn responder_reply(&mut self, m1: &[u8]) -> Result<Vec<u8>, CoreError> {
        self.check_clean(false)?;
        if self.e_secret.is_some() || m1.len() != M1_LEN {
            return Err(CoreError::Malformed);
        }
        let (e_cli, ek_cli) = (&m1[..P384_PUB], &m1[P384_PUB..]);
        // Received values mixed first, in send order (else transcript forks).
        self.sym.mix_hash(e_cli);
        self.sym.mix_hash(ek_cli);
        let (e_sk, e_pub) = p384_keygen()?;
        self.e_secret = Some(e_sk);
        self.sym.mix_hash(&e_pub);
        // Encapsulate to the initiator's KEM key (mirrors `kem.rs`).
        use ml_kem::Key as MlkemKey;
        let ek_arr: [u8; MLKEM1024_PK] = ek_cli.try_into().map_err(|_| CoreError::Malformed)?;
        let ek_key: MlkemKey<EncapsulationKey<MlKem1024>> = ek_arr.into();
        let ek = EncapsulationKey::<MlKem1024>::new(&ek_key).map_err(|_| CoreError::Malformed)?;
        let (ml_ct, ml_ss) = ek.encapsulate();
        let ct_bytes = ml_ct.to_vec();
        if ct_bytes.len() != MLKEM1024_CT {
            return Err(CoreError::Malformed);
        }
        self.sym.mix_hash(&ct_bytes);
        // ee then ff (KEM ss), each MixKey — single-use ECDH secret dropped.
        let e_taken = self.e_secret.take().ok_or(CoreError::Malformed)?;
        let ee = p384_dh(&e_taken, e_cli)?;
        self.sym.mix_key(&ee)?;
        let mut ee_z = ee;
        ee_z.zeroize();
        self.sym.mix_key(ml_ss.as_slice())?;
        let enc_pk = self.sym.encrypt_and_hash(&self.sig_pk)?;
        let h_for_sig = self.sym.h;
        let sk = self.sig_sk.as_ref().ok_or(CoreError::Malformed)?;
        let mut sig = sk.sign(DOMAIN_SIG_RESP, &h_for_sig);
        // Verify-after-sign fault detection (mirrors `_sign(..., pk=...)`).
        let own_vk = Mldsa87VerifyingKey::from_bytes(&self.sig_pk)?;
        if own_vk.verify(DOMAIN_SIG_RESP, &h_for_sig, &sig).is_err() {
            sig.zeroize();
            self.quarantine();
            return Err(CoreError::Malformed);
        }
        let enc_sig = self.sym.encrypt_and_hash(&sig)?;
        sig.zeroize();
        if let Some(ref p) = self.psk {
            let mut pb = [0u8; 32];
            pb.copy_from_slice(&p[..]);
            self.sym.mix_key_and_hash(&pb)?;
            pb.zeroize();
        }
        let mut m2 = Vec::with_capacity(M2_LEN);
        m2.extend_from_slice(&e_pub);
        m2.extend_from_slice(&ct_bytes);
        m2.extend_from_slice(&enc_pk);
        m2.extend_from_slice(&enc_sig);
        if m2.len() != M2_LEN {
            self.quarantine();
            return Err(CoreError::Malformed);
        }
        Ok(m2)
    }

    /// Process M2: complete ee/ff, decrypt `s`, VERIFY responder sig BEFORE
    /// any derivation, then mandatory pin check (no unpinned path here).
    pub fn initiator_finish(&mut self, m2: &[u8], expected_pin: &[u8]) -> Result<(), CoreError> {
        self.check_clean(true)?;
        if expected_pin.len() != MLDSA87_PK {
            return Err(CoreError::Malformed);
        }
        if self.e_secret.is_none() || self.ml_dk.is_none() || self.peer_sig_pk.is_some() {
            return Err(CoreError::Malformed);
        }
        if m2.len() != M2_LEN {
            return Err(CoreError::Malformed);
        }
        let e_srv = &m2[..P384_PUB];
        let ml_ct = &m2[P384_PUB..P384_PUB + MLKEM1024_CT];
        let rest = &m2[P384_PUB + MLKEM1024_CT..];
        self.sym.mix_hash(e_srv);
        self.sym.mix_hash(ml_ct);
        let e_taken = self.e_secret.take().ok_or(CoreError::Malformed)?;
        let ee = p384_dh(&e_taken, e_srv)?;
        self.sym.mix_key(&ee)?;
        let mut ee_z = ee;
        ee_z.zeroize();
        let dk = self.ml_dk.take().ok_or(CoreError::Malformed)?;
        let ct_arr: [u8; MLKEM1024_CT] = ml_ct.try_into().map_err(|_| CoreError::Malformed)?;
        let ct: Ciphertext<MlKem1024> = ct_arr.into();
        let ml_ss = dk.decapsulate(&ct);
        self.sym.mix_key(ml_ss.as_slice())?;
        let (enc_pk, enc_sig) = (&rest[..MLDSA87_PK + TAG_LEN], &rest[MLDSA87_PK + TAG_LEN..]);
        let srv_pk = self.sym.decrypt_and_hash(enc_pk).map_err(|_| {
            self.quarantine();
            CoreError::BadSignature
        })?;
        if srv_pk.len() != MLDSA87_PK {
            self.quarantine();
            return Err(CoreError::Malformed);
        }
        let h_for_verify = self.sym.h;
        let srv_sig = self.sym.decrypt_and_hash(enc_sig).map_err(|_| {
            self.quarantine();
            CoreError::BadSignature
        })?;
        let srv_vk = Mldsa87VerifyingKey::from_bytes(&srv_pk)?;
        if srv_vk
            .verify(DOMAIN_SIG_RESP, &h_for_verify, &srv_sig)
            .is_err()
        {
            self.quarantine();
            return Err(CoreError::BadSignature);
        }
        // Mandatory pinning (constant-time; TOFU does not exist here).
        if !ct_eq(&srv_pk, expected_pin) {
            self.quarantine();
            return Err(CoreError::KeyMismatch);
        }
        self.peer_sig_pk = Some(srv_pk);
        if let Some(ref p) = self.psk {
            let mut pb = [0u8; 32];
            pb.copy_from_slice(&p[..]);
            self.sym.mix_key_and_hash(&pb)?;
            pb.zeroize();
        }
        Ok(())
    }

    /// M3: `-> s, se(sig)`. Exactly once per session (handshake-cipher
    /// nonce reuse would be forgery).
    pub fn initiator_complete(&mut self) -> Result<Vec<u8>, CoreError> {
        self.check_clean(true)?;
        if self.peer_sig_pk.is_none() || self.m3_done {
            return Err(CoreError::Malformed);
        }
        let enc_pk = self.sym.encrypt_and_hash(&self.sig_pk)?;
        let h_for_sig = self.sym.h;
        let sk = self.sig_sk.as_ref().ok_or(CoreError::Malformed)?;
        let mut sig = sk.sign(DOMAIN_SIG_INIT, &h_for_sig);
        let own_vk = Mldsa87VerifyingKey::from_bytes(&self.sig_pk)?;
        if own_vk.verify(DOMAIN_SIG_INIT, &h_for_sig, &sig).is_err() {
            sig.zeroize();
            self.quarantine();
            return Err(CoreError::Malformed);
        }
        let enc_sig = self.sym.encrypt_and_hash(&sig)?;
        sig.zeroize();
        self.m3_done = true;
        let mut m3 = Vec::with_capacity(M3_LEN);
        m3.extend_from_slice(&enc_pk);
        m3.extend_from_slice(&enc_sig);
        if m3.len() != M3_LEN {
            self.quarantine();
            return Err(CoreError::Malformed);
        }
        Ok(m3)
    }

    /// Process M3: decrypt `s`, VERIFY initiator sig BEFORE Split, pin check.
    pub fn responder_complete(&mut self, m3: &[u8], expected_pin: &[u8]) -> Result<(), CoreError> {
        self.check_clean(false)?;
        if expected_pin.len() != MLDSA87_PK {
            return Err(CoreError::Malformed);
        }
        if self.m3_done || m3.len() != M3_LEN {
            return Err(CoreError::Malformed);
        }
        let (enc_pk, enc_sig) = (&m3[..MLDSA87_PK + TAG_LEN], &m3[MLDSA87_PK + TAG_LEN..]);
        let cli_pk = self.sym.decrypt_and_hash(enc_pk).map_err(|_| {
            self.quarantine();
            CoreError::BadSignature
        })?;
        if cli_pk.len() != MLDSA87_PK {
            self.quarantine();
            return Err(CoreError::Malformed);
        }
        let h_for_verify = self.sym.h;
        let cli_sig = self.sym.decrypt_and_hash(enc_sig).map_err(|_| {
            self.quarantine();
            CoreError::BadSignature
        })?;
        let cli_vk = Mldsa87VerifyingKey::from_bytes(&cli_pk)?;
        if cli_vk
            .verify(DOMAIN_SIG_INIT, &h_for_verify, &cli_sig)
            .is_err()
        {
            self.quarantine();
            return Err(CoreError::BadSignature);
        }
        if !ct_eq(&cli_pk, expected_pin) {
            self.quarantine();
            return Err(CoreError::KeyMismatch);
        }
        self.peer_sig_pk = Some(cli_pk);
        self.m3_done = true;
        Ok(())
    }

    /// Split → `(k_send, k_recv, transcript_h)`; wipes handshake state.
    /// Usable exactly once; initiator M3 / responder M3 must precede.
    pub fn split(mut self) -> Result<SplitKeys, CoreError> {
        if self.quarantined || self.split_done || self.peer_sig_pk.is_none() {
            return Err(CoreError::Malformed);
        }
        if self.is_initiator && !self.m3_done {
            return Err(CoreError::Malformed);
        }
        if !self.is_initiator && !self.m3_done {
            return Err(CoreError::Malformed);
        }
        let out = finish_split(&self.sym, self.is_initiator)?;
        self.split_done = true;
        // `self` drops here: sym keys, ephemerals, PSK all wiped.
        Ok(out)
    }

    /// Construct an initiator session (signing key moved in, used at M3).
    pub fn initiator(
        sig_sk: Mldsa87SigningKey,
        sig_pk: Vec<u8>,
        psk: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        Self::new(true, sig_sk, sig_pk, psk)
    }

    /// Construct a responder session.
    pub fn responder(
        sig_sk: Mldsa87SigningKey,
        sig_pk: Vec<u8>,
        psk: Option<[u8; 32]>,
    ) -> Result<Self, CoreError> {
        Self::new(false, sig_sk, sig_pk, psk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Mldsa87SigningKey;

    fn identities() -> ((Mldsa87SigningKey, Vec<u8>), (Mldsa87SigningKey, Vec<u8>)) {
        let (ski, vki) = Mldsa87SigningKey::generate().unwrap();
        let (skr, vkr) = Mldsa87SigningKey::generate().unwrap();
        ((ski, vki.to_bytes()), (skr, vkr.to_bytes()))
    }

    #[test]
    fn full_handshake_roundtrip_agrees() {
        let ((ski, pki), (skr, pkr)) = identities();
        let mut init = Handshake::initiator(ski, pki.clone(), None).unwrap();
        let mut resp = Handshake::responder(skr, pkr.clone(), None).unwrap();
        let m1 = init.initiator_hello().unwrap();
        assert_eq!(m1.len(), M1_LEN);
        assert_eq!(m1[0], 0x04); // P-384 uncompressed prefix
        let m2 = resp.responder_reply(&m1).unwrap();
        assert_eq!(m2.len(), M2_LEN);
        init.initiator_finish(&m2, &pkr).unwrap();
        let m3 = init.initiator_complete().unwrap();
        assert_eq!(m3.len(), M3_LEN);
        resp.responder_complete(&m3, &pki).unwrap();
        let (ik_s, ik_r, ih) = init.split().unwrap();
        let (rk_s, rk_r, rh) = resp.split().unwrap();
        // Crossed keys agree; transcripts agree.
        assert_eq!(ik_s, rk_r);
        assert_eq!(ik_r, rk_s);
        assert_eq!(ih, rh);
        assert_ne!(ik_s, ik_r);
        // Frame-key + ratchet-root derives agree cross-role.
        assert_eq!(
            derive_shared_frame_key(&ik_s, &ik_r, &ih, true),
            derive_shared_frame_key(&rk_s, &rk_r, &rh, false)
        );
        let (rr_i, _) = derive_double_ratchet_root(&ik_s, &ik_r, &ih, true);
        let (rr_r, _) = derive_double_ratchet_root(&rk_s, &rk_r, &rh, false);
        assert_eq!(rr_i, rr_r);
    }

    #[test]
    fn psk_variant_agrees_and_differs() {
        let ((ski, pki), (skr, pkr)) = identities();
        let psk = [0x5Au8; 32];
        let mut init = Handshake::initiator(ski, pki.clone(), Some(psk)).unwrap();
        let mut resp = Handshake::responder(skr, pkr.clone(), Some(psk)).unwrap();
        let m1 = init.initiator_hello().unwrap();
        let m2 = resp.responder_reply(&m1).unwrap();
        init.initiator_finish(&m2, &pkr).unwrap();
        let m3 = init.initiator_complete().unwrap();
        resp.responder_complete(&m3, &pki).unwrap();
        let (ik_s, _, _) = init.split().unwrap();
        // Same flow without PSK must derive DIFFERENT keys (PSK binds).
        let ((ski2, pki2), (skr2, pkr2)) = identities();
        let mut i2 = Handshake::initiator(ski2, pki2.clone(), None).unwrap();
        let mut r2 = Handshake::responder(skr2, pkr2.clone(), None).unwrap();
        let m1b = i2.initiator_hello().unwrap();
        let m2b = r2.responder_reply(&m1b).unwrap();
        i2.initiator_finish(&m2b, &pkr2).unwrap();
        let m3b = i2.initiator_complete().unwrap();
        r2.responder_complete(&m3b, &pki2).unwrap();
        let (jk_s, _, _) = i2.split().unwrap();
        assert_ne!(ik_s, jk_s);
    }

    #[test]
    fn wrong_pin_tamper_replay_fail_closed() {
        let ((ski, pki), (skr, pkr)) = identities();
        let mut init = Handshake::initiator(ski, pki.clone(), None).unwrap();
        let mut resp = Handshake::responder(skr, pkr.clone(), None).unwrap();
        let m1 = init.initiator_hello().unwrap();
        // Truncated M1 refused.
        assert!(resp.responder_reply(&m1[..100]).is_err());
        let m2 = resp.responder_reply(&m1).unwrap();
        // Wrong pin refused (constant-time compare, then latch).
        let mut wrong = pkr.clone();
        wrong[0] ^= 1;
        assert_eq!(
            init.initiator_finish(&m2, &wrong).unwrap_err(),
            CoreError::KeyMismatch
        );
        // Latched: even the right pin now fails.
        assert!(init.initiator_finish(&m2, &pkr).is_err());
        // Tampered M2 refused on a fresh session.
        let ((ski3, pki3), (skr3, pkr3)) = identities();
        let mut i3 = Handshake::initiator(ski3, pki3.clone(), None).unwrap();
        let mut r3 = Handshake::responder(skr3, pkr3.clone(), None).unwrap();
        let m1b = i3.initiator_hello().unwrap();
        let mut m2b = r3.responder_reply(&m1b).unwrap();
        m2b[2000] ^= 1;
        assert!(i3.initiator_finish(&m2b, &pkr3).is_err());
        // M3 replay / double-complete refused.
        let ((a, pa), (b, pb)) = identities();
        let mut x = Handshake::initiator(a, pa.clone(), None).unwrap();
        let mut y = Handshake::responder(b, pb.clone(), None).unwrap();
        let q1 = x.initiator_hello().unwrap();
        let q2 = y.responder_reply(&q1).unwrap();
        x.initiator_finish(&q2, &pb).unwrap();
        let q3 = x.initiator_complete().unwrap();
        assert!(x.initiator_complete().is_err()); // exactly once
        y.responder_complete(&q3, &pa).unwrap();
        assert!(y.responder_complete(&q3, &pa).is_err()); // no replay
    }
}
