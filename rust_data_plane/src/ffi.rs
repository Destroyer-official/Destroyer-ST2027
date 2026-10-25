//! Thin PyO3 control-plane bindings for the Rust secure core.
//!
//! DISCIPLINE (enforced by review, not by the type system):
//! - Python is orchestration ONLY. Session keys returned across this
//!   boundary land in CPython `bytes` (GC-copied, unwipable). Callers MUST
//!   feed them straight into `SecureEngine::establish_session` (Rust memory)
//!   and drop/overwrite the Python copy immediately. Long-lived secrets
//!   MUST live in `CoreRatchet` / `CoreKexResponder` (Rust memory), never
//!   in Python variables.
//! - Errors are coarse (`CoreError` display) — no oracle detail crosses.
//! - Signing keys never cross: `CoreMldsaSigner` holds the key in Rust;
//!   only signatures (public) and verifying keys (public) cross.
//!
//! Reference behavior mirrors the Python backup tree; production guarantees
//! live in the wrapped modules (`auth`, `kex_auth`, `ratchet`, `attest`).

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use zeroize::Zeroizing;

use crate::attest::{
    appraise as attest_appraise, evaluate_policy, Evidence, Posture, TrustAnchorStore,
};
use crate::auth::{Mldsa87SigningKey, Mldsa87VerifyingKey};
use crate::handshake::Handshake;
use crate::kem::{EphemeralKeys, HYBRID_SS};
use crate::kex_auth::{
    initiator_begin, initiator_finish, responder_complete, transcript, AuthMaterial,
    INITIATOR_BUNDLE_LEN, RESPONDER_BUNDLE_LEN,
};
use crate::policy::{NONCE_LEN, TRANSCRIPT_LEN};
use crate::ratchet::PcsRatchet;
use crate::session::Transport;

fn err(e: crate::policy::CoreError) -> PyErr {
    PyValueError::new_err(format!("secure-core: {e}"))
}

fn psk32(v: Vec<u8>) -> Result<[u8; 32], PyErr> {
    if v.len() != 32 {
        return Err(PyValueError::new_err("psk must be 32 bytes"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

/// ML-DSA-87 signer held in Rust memory. The signing key never crosses FFI.
#[pyclass]
pub struct CoreMldsaSigner {
    inner: Option<Mldsa87SigningKey>,
}

#[pymethods]
impl CoreMldsaSigner {
    #[new]
    pub fn new() -> PyResult<Self> {
        let (sk, _) = Mldsa87SigningKey::generate().map_err(err)?;
        Ok(Self { inner: Some(sk) })
    }

    /// Verifying-key bytes (2592, public — safe to pin/distribute).
    pub fn verifying_bytes(&self) -> PyResult<Vec<u8>> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("signer consumed"))?
            .verifying_bytes())
    }

    /// Sign `domain || message`. Domain must be a policy constant.
    pub fn sign(&self, domain: Vec<u8>, message: Vec<u8>) -> PyResult<Vec<u8>> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("signer consumed"))?
            .sign(&domain, &message))
    }

    /// Verify with an enrolled key (static; no secret involved).
    #[staticmethod]
    pub fn verify(
        vk_bytes: Vec<u8>,
        domain: Vec<u8>,
        message: Vec<u8>,
        sig: Vec<u8>,
    ) -> PyResult<()> {
        let vk = Mldsa87VerifyingKey::from_bytes(&vk_bytes).map_err(err)?;
        vk.verify(&domain, &message, &sig).map_err(err)
    }
}

/// KEX responder: holds the ephemeral bundle in Rust; completes with
/// PSK and/or ML-DSA transcript-signature legs (verify-before-derive).
#[pyclass]
pub struct CoreKexResponder {
    keys: Option<EphemeralKeys>,
}

// Plain-Rust helper (NOT exposed to Python: `AuthMaterial` is a Rust type).
impl CoreKexResponder {
    fn finish_raw(
        this: &CoreKexResponder,
        ib: Vec<u8>,
        auth: &AuthMaterial<'_>,
    ) -> PyResult<(Vec<u8>, Vec<u8>, String)> {
        if ib.len() != INITIATOR_BUNDLE_LEN {
            return Err(PyValueError::new_err("initiator bundle malformed"));
        }
        let k = this
            .keys
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("responder consumed"))?;
        let s = responder_complete(k, &ib, auth).map_err(err)?;
        Ok((
            s.session_key().to_vec(),
            s.transcript().to_vec(),
            s.sas_string(),
        ))
    }
}

#[pymethods]
impl CoreKexResponder {
    #[new]
    pub fn new() -> PyResult<Self> {
        Ok(Self {
            keys: Some(
                EphemeralKeys::generate()
                    .map_err(|_| PyValueError::new_err("kex keygen failed"))?,
            ),
        })
    }

    /// Our bundle `x_pub(32) || ml_ek(1568)` to send to the initiator.
    pub fn bundle(&self) -> PyResult<Vec<u8>> {
        let k = self
            .keys
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("responder consumed"))?;
        let mut b = Vec::with_capacity(RESPONDER_BUNDLE_LEN);
        b.extend_from_slice(&k.x_public);
        b.extend_from_slice(&k.ml_ek);
        Ok(b)
    }

    /// Complete with a 32-byte PSK leg.
    pub fn complete_psk(&self, ib: Vec<u8>, psk: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>, String)> {
        let p = psk32(psk)?;
        let r = Self::finish_raw(self, ib, &AuthMaterial::Psk(&p));
        let mut z = Zeroizing::new(p);
        use zeroize::Zeroize;
        z.zeroize();
        r
    }

    /// Complete with ML-DSA legs (both directions verified pre-derive).
    pub fn complete_sigs(
        &self,
        ib: Vec<u8>,
        r_vk: Vec<u8>,
        r_sig: Vec<u8>,
        i_vk: Vec<u8>,
        i_sig: Vec<u8>,
    ) -> PyResult<(Vec<u8>, Vec<u8>, String)> {
        let rv = Mldsa87VerifyingKey::from_bytes(&r_vk).map_err(err)?;
        let iv = Mldsa87VerifyingKey::from_bytes(&i_vk).map_err(err)?;
        Self::finish_raw(
            self,
            ib,
            &AuthMaterial::Signatures {
                responder_vk: &rv,
                responder_sig: &r_sig,
                initiator_vk: &iv,
                initiator_sig: &i_sig,
            },
        )
    }
}

/// KEX initiator phase-1 handle: holds `(rb, ib, hybrid)` in Rust between
/// bundle exchange (phase 1) and transcript-signature verification (phase 2).
/// Signatures can only exist after both bundles are known.
#[pyclass]
pub struct CoreKexInitiator {
    rb: Vec<u8>,
    ib: Vec<u8>,
    hybrid: Option<Zeroizing<[u8; HYBRID_SS]>>,
}

// Plain-Rust helper (NOT exposed: `Zeroizing` is not a Python object).
impl CoreKexInitiator {
    fn take_hybrid(&mut self) -> PyResult<Zeroizing<[u8; HYBRID_SS]>> {
        self.hybrid
            .take()
            .ok_or_else(|| PyValueError::new_err("initiator already finished"))
    }
}

#[pymethods]
impl CoreKexInitiator {
    #[new]
    pub fn begin(responder_bundle: Vec<u8>) -> PyResult<Self> {
        let (ib, hybrid) = initiator_begin(&responder_bundle).map_err(err)?;
        Ok(Self {
            rb: responder_bundle,
            ib,
            hybrid: Some(hybrid),
        })
    }

    /// Our initiator bundle to send to the responder.
    pub fn bundle(&self) -> Vec<u8> {
        self.ib.clone()
    }

    /// Transcript `SHA-384(rb || ib)` — sign this (both sides) out-of-band.
    pub fn transcript(&self) -> PyResult<Vec<u8>> {
        Ok(transcript(&self.rb, &self.ib).map_err(err)?.to_vec())
    }

    /// Finish with a 32-byte PSK leg. Returns `(session_key, transcript, sas)`.
    pub fn finish_psk(&mut self, psk: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>, String)> {
        let p = psk32(psk)?;
        let h = self.take_hybrid()?;
        let r = initiator_finish(&self.rb, &self.ib, &h, &AuthMaterial::Psk(&p)).map_err(err)?;
        let mut z = Zeroizing::new(p);
        use zeroize::Zeroize;
        z.zeroize();
        Ok((
            r.session_key().to_vec(),
            r.transcript().to_vec(),
            r.sas_string(),
        ))
    }

    /// Finish with ML-DSA legs (verified pre-derive).
    pub fn finish_sigs(
        &mut self,
        r_vk: Vec<u8>,
        r_sig: Vec<u8>,
        i_vk: Vec<u8>,
        i_sig: Vec<u8>,
    ) -> PyResult<(Vec<u8>, Vec<u8>, String)> {
        let rv = Mldsa87VerifyingKey::from_bytes(&r_vk).map_err(err)?;
        let iv = Mldsa87VerifyingKey::from_bytes(&i_vk).map_err(err)?;
        let h = self.take_hybrid()?;
        let r = initiator_finish(
            &self.rb,
            &self.ib,
            &h,
            &AuthMaterial::Signatures {
                responder_vk: &rv,
                responder_sig: &r_sig,
                initiator_vk: &iv,
                initiator_sig: &i_sig,
            },
        )
        .map_err(err)?;
        Ok((
            r.session_key().to_vec(),
            r.transcript().to_vec(),
            r.sas_string(),
        ))
    }
}

/// Fresh-KEM PCS ratchet held in Rust memory. No legacy mode exists.
#[pyclass]
pub struct CoreRatchet {
    inner: Option<PcsRatchet>,
}

#[pymethods]
impl CoreRatchet {
    #[new]
    pub fn new(session_key: Vec<u8>) -> PyResult<Self> {
        let a = psk32(session_key)?;
        Ok(Self {
            inner: Some(PcsRatchet::new(&a).map_err(err)?),
        })
    }

    /// Currently advertised `(x_pub, ek)` pair.
    pub fn advertise(&self) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let (x, ek) = self
            .inner
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("ratchet consumed"))?
            .advertise();
        Ok((x.to_vec(), ek))
    }

    pub fn epoch(&self) -> PyResult<u64> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("ratchet consumed"))?
            .epoch())
    }

    /// Sending step. Returns `(eph_x_pub, ml_ct, next_x_pub, next_ek, epoch, msg_key)`.
    #[allow(clippy::type_complexity)]
    pub fn send_step(
        &mut self,
        peer_x: Vec<u8>,
        peer_ek: Vec<u8>,
    ) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, u64, Vec<u8>)> {
        if peer_x.len() != 32 {
            return Err(PyValueError::new_err("peer_x_pub must be 32 bytes"));
        }
        let mut xa = [0u8; 32];
        xa.copy_from_slice(&peer_x);
        let r = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("ratchet consumed"))?;
        let (step, key) = r.send_step(&xa, &peer_ek).map_err(err)?;
        Ok((
            step.eph_x_pub.to_vec(),
            step.ml_ct,
            step.next_x_pub.to_vec(),
            step.next_ek,
            step.epoch,
            key.to_vec(),
        ))
    }

    /// Receiving step. Returns the message key.
    pub fn receive_step(&mut self, eph_x: Vec<u8>, ml_ct: Vec<u8>) -> PyResult<Vec<u8>> {
        if eph_x.len() != 32 {
            return Err(PyValueError::new_err("eph_x_pub must be 32 bytes"));
        }
        let mut xa = [0u8; 32];
        xa.copy_from_slice(&eph_x);
        Ok(self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("ratchet consumed"))?
            .receive_step(&xa, &ml_ct)
            .map_err(err)?
            .to_vec())
    }
}

/// Enrollment-bound attestation store (RATS verifier). No TOFU path.
#[pyclass]
pub struct CoreAttestStore {
    inner: TrustAnchorStore,
}

impl Default for CoreAttestStore {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl CoreAttestStore {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: TrustAnchorStore::new(),
        }
    }

    /// Enroll `kid -> ML-DSA-87 public bytes` out-of-band.
    pub fn enroll(&mut self, kid: String, pub_bytes: Vec<u8>) -> PyResult<()> {
        self.inner.enroll(&kid, pub_bytes).map_err(err)
    }

    /// Appraise evidence. `message` is the caller-constructed canonical
    /// posture binding; `domain` the attestation domain string.
    #[allow(clippy::too_many_arguments)]
    pub fn appraise(
        &self,
        kid: String,
        pub_bytes: Vec<u8>,
        sig: Vec<u8>,
        message: Vec<u8>,
        nonce: Vec<u8>,
        expected_nonce: Vec<u8>,
        ts: f64,
        vk_bytes: Vec<u8>,
        domain: Vec<u8>,
    ) -> PyResult<()> {
        if nonce.len() != NONCE_LEN || expected_nonce.len() != NONCE_LEN {
            return Err(PyValueError::new_err("nonce must be 32 bytes"));
        }
        let vk = Mldsa87VerifyingKey::from_bytes(&vk_bytes).map_err(err)?;
        let ev = Evidence {
            kid: &kid,
            pub_bytes: &pub_bytes,
            sig: &sig,
            message: &message,
            nonce: &nonce,
            expected_nonce: &expected_nonce,
            ts,
            now: None,
        };
        attest_appraise(&self.inner, &ev, &vk, &domain).map_err(err)
    }

    /// Pure posture-policy check (no I/O).
    #[staticmethod]
    pub fn check_posture(
        secure_boot: bool,
        vbs: bool,
        hvci: bool,
        measured: bool,
        native: bool,
    ) -> PyResult<()> {
        evaluate_policy(&Posture {
            secure_boot,
            vbs_enforced: vbs,
            hvci_running: hvci,
            measured_boot: measured,
            native_core: native,
        })
        .map_err(err)
    }
}

/// Transcript length (48, SHA-384) for orchestrator buffer checks.
#[pyfunction]
pub fn transcript_len() -> usize {
    TRANSCRIPT_LEN
}

/// Shared frame key over split keys (byte-identical to
/// `noise_pq.derive_shared_frame_key`). Exposed so orchestrators and the
/// cross-implementation interop test can compare vectors bit-for-bit.
#[pyfunction]
pub fn derive_frame_key(
    k_send: Vec<u8>,
    k_recv: Vec<u8>,
    h: Vec<u8>,
    is_initiator: bool,
) -> PyResult<Vec<u8>> {
    let a = psk32(k_send)?;
    let b = psk32(k_recv)?;
    if h.len() != crate::handshake::HASHLEN {
        return Err(PyValueError::new_err("transcript must be 48 bytes"));
    }
    let mut hh = [0u8; crate::handshake::HASHLEN];
    hh.copy_from_slice(&h);
    Ok(crate::handshake::derive_shared_frame_key(&a, &b, &hh, is_initiator).to_vec())
}

/// Canonical certificate TBS bytes (byte-identical to
/// `trust_anchor.tbs_bytes`). Exposed for cross-implementation checks.
#[pyfunction]
pub fn pki_tbs_bytes(
    serial: Vec<u8>,
    subject: String,
    subject_pk: Vec<u8>,
    not_before: u64,
    not_after: u64,
) -> PyResult<Vec<u8>> {
    crate::pki::tbs_bytes(&serial, &subject, &subject_pk, not_before, not_after).map_err(err)
}

/// Canonical revocation bytes (byte-identical to `trust_anchor.revoke_bytes`).
#[pyfunction]
pub fn pki_revoke_bytes(serial: Vec<u8>, reason: String, ts: f64, seq: u64) -> PyResult<Vec<u8>> {
    crate::pki::revoke_bytes(&serial, &reason, ts, seq).map_err(err)
}

/// Double-ratchet root over split keys (byte-identical to
/// `noise_pq.derive_double_ratchet_root`). Returns `(root_key, transcript)`.
#[pyfunction]
pub fn derive_ratchet_root(
    k_send: Vec<u8>,
    k_recv: Vec<u8>,
    h: Vec<u8>,
    is_initiator: bool,
) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let a = psk32(k_send)?;
    let b = psk32(k_recv)?;
    if h.len() != crate::handshake::HASHLEN {
        return Err(PyValueError::new_err("transcript must be 48 bytes"));
    }
    let mut hh = [0u8; crate::handshake::HASHLEN];
    hh.copy_from_slice(&h);
    let (root, t) = crate::handshake::derive_double_ratchet_root(&a, &b, &hh, is_initiator);
    Ok((root.to_vec(), t.to_vec()))
}

/// Noise_XXhfs initiator (P-384 + ML-KEM-1024 + ML-DSA-87), identity key
/// generated and held in Rust. Pinning mandatory (`expected_pin`).
#[pyclass]
pub struct CoreHsInitiator {
    inner: Option<Handshake>,
    identity: Vec<u8>,
}

#[pymethods]
impl CoreHsInitiator {
    #[new]
    pub fn new() -> PyResult<Self> {
        let (sk, vk) = Mldsa87SigningKey::generate().map_err(err)?;
        let vk_bytes = vk.to_bytes();
        Ok(Self {
            inner: Some(Handshake::initiator(sk, vk_bytes.clone(), None).map_err(err)?),
            identity: vk_bytes,
        })
    }

    /// This side's ML-DSA-87 identity (public — pin it out-of-band).
    pub fn identity(&self) -> Vec<u8> {
        self.identity.clone()
    }

    /// M1 (`e_pub || ml_ek`, 1665 bytes).
    pub fn hello(&mut self) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("handshake consumed"))?
            .initiator_hello()
            .map_err(err)
    }

    /// Process M2 with mandatory peer pin.
    pub fn finish(&mut self, m2: Vec<u8>, expected_pin: Vec<u8>) -> PyResult<()> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("handshake consumed"))?
            .initiator_finish(&m2, &expected_pin)
            .map_err(err)
    }

    /// Emit M3 (exactly once).
    pub fn complete(&mut self) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("handshake consumed"))?
            .initiator_complete()
            .map_err(err)
    }

    /// Split → `(k_send, k_recv, transcript_h)`. Consumes the session.
    pub fn split(&mut self) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let h = self
            .inner
            .take()
            .ok_or_else(|| PyValueError::new_err("handshake consumed"))?;
        let (a, b, t) = h.split().map_err(err)?;
        Ok((a.to_vec(), b.to_vec(), t.to_vec()))
    }
}

/// Noise_XXhfs responder. Identity held in Rust; pinning mandatory.
#[pyclass]
pub struct CoreHsResponder {
    inner: Option<Handshake>,
    identity: Vec<u8>,
}

#[pymethods]
impl CoreHsResponder {
    #[new]
    pub fn new() -> PyResult<Self> {
        let (sk, vk) = Mldsa87SigningKey::generate().map_err(err)?;
        let vk_bytes = vk.to_bytes();
        Ok(Self {
            inner: Some(Handshake::responder(sk, vk_bytes.clone(), None).map_err(err)?),
            identity: vk_bytes,
        })
    }

    /// This side's ML-DSA-87 identity (public — pin it out-of-band).
    pub fn identity(&self) -> Vec<u8> {
        self.identity.clone()
    }

    /// Process M1 → M2 (8916 bytes).
    pub fn reply(&mut self, m1: Vec<u8>) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("handshake consumed"))?
            .responder_reply(&m1)
            .map_err(err)
    }

    /// Process M3 with mandatory peer pin.
    pub fn complete(&mut self, m3: Vec<u8>, expected_pin: Vec<u8>) -> PyResult<()> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("handshake consumed"))?
            .responder_complete(&m3, &expected_pin)
            .map_err(err)
    }

    /// Split → `(k_send, k_recv, transcript_h)`. Consumes the session.
    pub fn split(&mut self) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let h = self
            .inner
            .take()
            .ok_or_else(|| PyValueError::new_err("handshake consumed"))?;
        let (a, b, t) = h.split().map_err(err)?;
        Ok((a.to_vec(), b.to_vec(), t.to_vec()))
    }
}

/// Post-handshake transport over split keys (wire-identical to
/// `noise_pq.transport_send/recv`: `seqBE || AES-GCM(k, seqBE||dir||0³,
/// pt, "NPQ1")`, replay check → verify → mark).
#[pyclass]
pub struct CoreTransport {
    inner: Option<Transport>,
}

#[pymethods]
impl CoreTransport {
    #[new]
    pub fn new(k_send: Vec<u8>, k_recv: Vec<u8>, is_initiator: bool) -> PyResult<Self> {
        let a = psk32(k_send)?;
        let b = psk32(k_recv)?;
        Ok(Self {
            inner: Some(Transport::new(a, b, is_initiator)),
        })
    }

    /// Seal one message → wire bytes.
    pub fn send(&mut self, pt: Vec<u8>) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("transport closed"))?
            .send(&pt)
            .map_err(err)
    }

    /// Open one wire message (replay/tamper fail closed).
    pub fn recv(&mut self, wire: Vec<u8>) -> PyResult<Vec<u8>> {
        self.inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("transport closed"))?
            .recv(&wire)
            .map_err(err)
    }
}

use crate::acd::{ActiveCyberDefenseEngine, DefensivePlaybook, ThreatTrigger};
use crate::cookie::StatelessCookieGate;
use crate::zero_trust::{
    inspect_content_rtb, ClearanceLevel, SecurityRole, ZeroTrustEngine, MIN_TRUST_THRESHOLD,
};

#[pyclass]
pub struct CoreCookieGate {
    inner: StatelessCookieGate,
}

#[pymethods]
impl CoreCookieGate {
    #[new]
    #[pyo3(signature = (rotation_interval=None, max_cached=None))]
    pub fn new(rotation_interval: Option<u64>, max_cached: Option<usize>) -> Self {
        Self {
            inner: StatelessCookieGate::new(
                rotation_interval.unwrap_or(crate::cookie::DEFAULT_ROTATION_SECS),
                max_cached.unwrap_or(8192),
            ),
        }
    }

    pub fn create_cookie(
        &mut self,
        client_ip: &str,
        client_port: u16,
        m1_prefix: Vec<u8>,
    ) -> Vec<u8> {
        self.inner.create_cookie(client_ip, client_port, &m1_prefix)
    }

    pub fn verify_cookie(
        &mut self,
        cookie: Vec<u8>,
        client_ip: &str,
        client_port: u16,
        m1_prefix: Vec<u8>,
    ) -> bool {
        self.inner
            .verify_cookie(&cookie, client_ip, client_port, &m1_prefix)
    }

    pub fn create_challenge(
        &mut self,
        client_ip: &str,
        client_port: u16,
        m1_prefix: Vec<u8>,
        difficulty_bits: u8,
    ) -> Vec<u8> {
        self.inner
            .create_challenge(client_ip, client_port, &m1_prefix, difficulty_bits)
    }

    pub fn verify_response(
        &mut self,
        response: Vec<u8>,
        client_ip: &str,
        client_port: u16,
        m1_prefix: Vec<u8>,
        difficulty_bits: u8,
    ) -> bool {
        self.inner
            .verify_response(&response, client_ip, client_port, &m1_prefix, difficulty_bits)
    }

    #[staticmethod]
    #[pyo3(signature = (challenge_payload, max_iterations=None))]
    pub fn solve_challenge(
        challenge_payload: Vec<u8>,
        max_iterations: Option<u64>,
    ) -> Option<Vec<u8>> {
        StatelessCookieGate::solve_challenge(&challenge_payload, max_iterations.unwrap_or(2_000_000))
    }

    #[pyo3(signature = (wire, client_ip, client_port, require_cookie=false, difficulty_bits=0))]
    pub fn process_incoming_m1(
        &mut self,
        wire: Vec<u8>,
        client_ip: &str,
        client_port: u16,
        require_cookie: bool,
        difficulty_bits: u8,
    ) -> (String, Vec<u8>) {
        let (status, payload) = self.inner.process_incoming_m1(
            &wire,
            client_ip,
            client_port,
            require_cookie,
            difficulty_bits,
        );
        (status.to_string(), payload)
    }
}

#[pyclass]
pub struct CoreAcdEngine {
    pub(crate) inner: ActiveCyberDefenseEngine,
}

#[pymethods]
impl CoreAcdEngine {
    #[new]
    #[pyo3(signature = (replay_threshold=None, replay_window_secs=None, auth_fail_threshold=None, auth_fail_window_secs=None, quarantine_duration_secs=None))]
    pub fn new(
        replay_threshold: Option<usize>,
        replay_window_secs: Option<f64>,
        auth_fail_threshold: Option<usize>,
        auth_fail_window_secs: Option<f64>,
        quarantine_duration_secs: Option<f64>,
    ) -> Self {
        Self {
            inner: ActiveCyberDefenseEngine::new(
                replay_threshold.unwrap_or(3),
                replay_window_secs.unwrap_or(10.0),
                auth_fail_threshold.unwrap_or(5),
                auth_fail_window_secs.unwrap_or(30.0),
                quarantine_duration_secs.unwrap_or(300.0),
                None,
            ),
        }
    }

    pub fn is_quarantined(&self, source_id: &str) -> bool {
        self.inner.is_quarantined(source_id)
    }

    pub fn is_tactical_cloak_active(&self) -> bool {
        self.inner.is_tactical_cloak_active()
    }

    pub fn is_emergency_isolated(&self) -> bool {
        self.inner.is_emergency_isolated()
    }

    #[pyo3(signature = (source_id, duration_secs=None))]
    pub fn quarantine(&self, source_id: &str, duration_secs: Option<f64>) {
        let dur = duration_secs.map(std::time::Duration::from_secs_f64);
        self.inner.quarantine(source_id, dur);
    }

    pub fn record_event(&self, trigger_str: &str, source_id: &str) -> Option<String> {
        let trigger = match trigger_str {
            "replay" | "TRIGGER_REPLAY_BURST" => ThreatTrigger::ReplayBurst,
            "tamper" | "TRIGGER_TAMPER_DETECTED" => ThreatTrigger::TamperDetected,
            "auth_fail" | "TRIGGER_AUTH_FAILURE_FLOOD" => ThreatTrigger::AuthFailureFlood,
            "traffic" | "TRIGGER_TRAFFIC_ANOMALY" => ThreatTrigger::TrafficAnomaly,
            "fault" | "TRIGGER_KEY_EXPOSURE_RISK" => ThreatTrigger::FaultDetected,
            _ => return None,
        };
        self.inner.record_event(trigger, source_id).map(|pb| match pb {
            DefensivePlaybook::QuarantinePeer => "PLAYBOOK_QUARANTINE_PEER".to_string(),
            DefensivePlaybook::SeverSessionAndIsolate => "PLAYBOOK_SEVER_SESSION_AND_ISOLATE".to_string(),
            DefensivePlaybook::BlockSourceAndRekey => "PLAYBOOK_BLOCK_SOURCE_AND_REKEY".to_string(),
            DefensivePlaybook::ForceTacticalCloak => "PLAYBOOK_FORCE_TACTICAL_CLOAK".to_string(),
            DefensivePlaybook::PurgeEphemeralState => "PLAYBOOK_PURGE_EPHEMERAL_STATE".to_string(),
        })
    }
}

#[pyclass]
pub struct CoreZeroTrustEngine {
    pub(crate) inner: ZeroTrustEngine,
}

#[pymethods]
impl CoreZeroTrustEngine {
    #[new]
    #[pyo3(signature = (min_threshold=None))]
    pub fn new(min_threshold: Option<u32>) -> Self {
        Self {
            inner: ZeroTrustEngine::new(min_threshold.unwrap_or(MIN_TRUST_THRESHOLD)),
        }
    }

    pub fn register_peer(&self, peer_id: &str, role_str: &str) -> PyResult<()> {
        let role = match role_str.to_lowercase().as_str() {
            "admin" => SecurityRole::Admin,
            "operator" => SecurityRole::Operator,
            "viewer" => SecurityRole::Viewer,
            _ => return Err(PyValueError::new_err("invalid role: expected admin, operator, or viewer")),
        };
        self.inner.register_peer(peer_id, role);
        Ok(())
    }

    pub fn authorize(&self, peer_id: &str, perm_mask: u32) -> PyResult<()> {
        self.inner.authorize(peer_id, perm_mask).map_err(err)
    }

    pub fn record_success(&self, peer_id: &str) -> PyResult<u32> {
        self.inner.record_success(peer_id).map_err(err)
    }

    pub fn record_penalty(&self, peer_id: &str, penalty: u32) -> PyResult<u32> {
        self.inner.record_penalty(peer_id, penalty).map_err(err)
    }

    pub fn trust_score(&self, peer_id: &str) -> Option<u32> {
        self.inner.trust_score(peer_id)
    }

    pub fn is_trusted(&self, peer_id: &str) -> bool {
        self.inner.is_trusted(peer_id)
    }

    pub fn verify_read(
        &self,
        subject_clearance: u8,
        subject_caveats: u32,
        object_classification: u8,
        object_caveats: u32,
    ) -> PyResult<bool> {
        let sc = ClearanceLevel::from_u8(subject_clearance).map_err(err)?;
        let oc = ClearanceLevel::from_u8(object_classification).map_err(err)?;
        Ok(self
            .inner
            .verify_read(sc, subject_caveats, oc, object_caveats)
            .is_ok())
    }

    pub fn verify_write(
        &self,
        subject_clearance: u8,
        target_classification: u8,
    ) -> PyResult<bool> {
        let sc = ClearanceLevel::from_u8(subject_clearance).map_err(err)?;
        let tc = ClearanceLevel::from_u8(target_classification).map_err(err)?;
        Ok(self.inner.verify_write(sc, tc).is_ok())
    }

    pub fn inspect_content(&self, data: &[u8]) -> (bool, Option<String>) {
        match inspect_content_rtb(data) {
            Ok(()) => (true, None),
            Err(marker) => (false, Some(marker.to_string())),
        }
    }
}

#[pyclass]
pub struct CoreMemoryGuard;

#[pymethods]
impl CoreMemoryGuard {
    #[staticmethod]
    pub fn secure_wipe(buf: &Bound<'_, pyo3::types::PyByteArray>) -> PyResult<()> {
        unsafe {
            let slice = buf.as_bytes_mut();
            let len = slice.len();
            if len > 0 {
                let ptr = slice.as_mut_ptr();
                std::ptr::write_bytes(ptr, 0x00, len);
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                std::ptr::write_bytes(ptr, 0xFF, len);
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                let _ = getrandom::fill(slice);
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                std::ptr::write_bytes(ptr, 0x00, len);
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            }
        }
        Ok(())
    }
}

#[pyclass]
pub struct CoreGroupRatchet {
    inner: crate::group_ratchet::SovereignGroupRatchet,
}

#[pymethods]
impl CoreGroupRatchet {
    #[new]
    pub fn new(
        group_id: String,
        local_member_id: String,
        initial_epoch_secret: Vec<u8>,
    ) -> PyResult<Self> {
        if initial_epoch_secret.len() != 48 {
            return Err(PyValueError::new_err("initial_epoch_secret must be 48 bytes"));
        }
        let mut secret = [0u8; 48];
        secret.copy_from_slice(&initial_epoch_secret);
        let inner = crate::group_ratchet::SovereignGroupRatchet::new(
            group_id, local_member_id, secret,
        )
        .map_err(|e| PyValueError::new_err(format!("GroupRatchet error: {e:?}")))?;
        Ok(Self { inner })
    }

    pub fn add_member(&mut self, member_id: String, chain_key: Vec<u8>) -> PyResult<()> {
        if chain_key.len() != 48 {
            return Err(PyValueError::new_err("chain_key must be 48 bytes"));
        }
        let mut key = [0u8; 48];
        key.copy_from_slice(&chain_key);
        self.inner.add_member(member_id, key);
        Ok(())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .encrypt_group_message(plaintext)
            .map_err(|e| PyValueError::new_err(format!("GroupRatchet encryption failed: {e:?}")))
    }

    pub fn decrypt(&mut self, sender_id: &str, wire_frame: &[u8]) -> PyResult<Vec<u8>> {
        self.inner
            .decrypt_group_message(sender_id, wire_frame)
            .map_err(|e| PyValueError::new_err(format!("GroupRatchet decryption failed: {e:?}")))
    }

    pub fn advance_epoch(&mut self, fresh_entropy: Vec<u8>) -> PyResult<u64> {
        if fresh_entropy.len() != 48 {
            return Err(PyValueError::new_err("fresh_entropy must be 48 bytes"));
        }
        let mut entropy = [0u8; 48];
        entropy.copy_from_slice(&fresh_entropy);
        self.inner
            .advance_epoch(&entropy)
            .map_err(|e| PyValueError::new_err(format!("GroupRatchet advance_epoch failed: {e:?}")))
    }

    #[getter]
    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }

    #[getter]
    pub fn group_id(&self) -> String {
        self.inner.group_id.clone()
    }

    #[getter]
    pub fn local_member_id(&self) -> String {
        self.inner.local_member_id.clone()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CoreMldsaSigner>()?;
    m.add_class::<CoreKexResponder>()?;
    m.add_class::<CoreKexInitiator>()?;
    m.add_class::<CoreRatchet>()?;
    m.add_class::<CoreAttestStore>()?;
    m.add_class::<CoreHsInitiator>()?;
    m.add_class::<CoreHsResponder>()?;
    m.add_class::<CoreTransport>()?;
    m.add_class::<CoreCookieGate>()?;
    m.add_class::<CoreAcdEngine>()?;
    m.add_class::<CoreZeroTrustEngine>()?;
    m.add_class::<CoreMemoryGuard>()?;
    m.add_class::<CoreGroupRatchet>()?;
    m.add_function(wrap_pyfunction!(transcript_len, m)?)?;
    m.add_function(wrap_pyfunction!(derive_frame_key, m)?)?;
    m.add_function(wrap_pyfunction!(derive_ratchet_root, m)?)?;
    m.add_function(wrap_pyfunction!(pki_tbs_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(pki_revoke_bytes, m)?)?;
    Ok(())
}
