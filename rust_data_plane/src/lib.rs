//! destroyer_core — Rust secure core + data plane for direct-IPv6 P2P.
//!
//! ## Rust-first architecture (Python kept as reference/backup)
//!
//! The Rust core is the PRODUCTION path: always fail-closed, no
//! environment-variable downgrades, no TOFU, no legacy ratchet, no argv
//! secrets. The Python tree (`noise_pq.py`, `double_ratchet.py`,
//! `secure_transmit_2027.py`, `trust_anchor.py`, `ts_attest.py`) is kept
//! INTACT as the audited reference and lab/backup path — see
//! `docs/RUST_CORE.md` for the module mapping. Python logic was not
//! rewritten; new production guarantees live here.
//!
//! Secure-core modules (NEW, strict-only):
//! - `policy`: single fail-closed truth (no opt-outs exist in Rust).
//! - `auth`: native ML-DSA-87 (FIPS 204, pure-Rust `ml-dsa` crate).
//! - `kex_auth`: authenticated hybrid KEX (X25519 + ML-KEM-1024,
//!   transcript-bound, PSK-or-MLDSA, SAS out-of-band).
//! - `ratchet`: fresh-KEM-per-step PCS ratchet (SPQR-style, no v1 reuse).
//! - `attest`: enrollment-bound RATS verifier (no TOFU path).
//! - `handshake`: Noise_XXhfs P-384+ML-KEM-1024+ML-DSA-87 handshake,
//!   byte-identical to the `noise_pq.py` reference profile.
//! - `session`: post-handshake transport + pipeline (frame key, ratchet
//!   root) matching `noise_pq` transport framing.
//! - `pki`: 3-of-5 threshold ML-DSA-87 verification, byte-identical TBS
//!   to `trust_anchor.py`.
//! - `keystore`: sealed key-file custody (0600 / exclusive / no argv).
//! - `ffi`: thin PyO3 control-plane bindings (orchestration only; secrets
//!   stay in Rust holders).
//!
//! Data-plane modules (existing, audited path): framing, AEAD, replay,
//! padding, chaff, silent-drop networking, FEC, pacing, purge.
//!
//! FFI discipline: bytes and counters cross the boundary; raw key material
//! never leaves Rust except inside sealed calls. All secrets ZeroizeOnDrop.

pub mod aead;
pub mod attest;
pub mod auth;
pub mod chaff;
pub mod ct;
pub mod fec;
pub mod ffi;
pub mod frame;
pub mod handshake;
pub mod kem;
pub mod kex_auth;
pub mod keystore;
pub mod memlock;
pub mod net;
pub mod nostd_microcore;
pub mod pacing;
pub mod pad;
pub mod pki;
pub mod policy;
pub mod purge;
pub mod ratchet;
pub mod replay;
pub mod session;

use crate::aead::{FrameKey, DIR_RECV, DIR_SEND};
use crate::frame::{pad_to_quantum, FTYPE_CHAFF, FTYPE_MSG};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass]
pub struct SecureEngine {
    replay: replay::AntiReplayWindow,
    is_connected: bool,
    key: Option<FrameKey>,
    send_seq: u64,
    /// Session role. The initiator seals with DIR_SEND and opens DIR_RECV;
    /// the responder does the opposite. Without this, simultaneous traffic
    /// in both directions would reuse (key, nonce) pairs and destroy the
    /// AEAD security of both streams.
    is_initiator: bool,
}

impl Default for SecureEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl SecureEngine {
    #[new]
    pub fn new() -> Self {
        SecureEngine {
            replay: replay::AntiReplayWindow::new(),
            is_connected: false,
            key: None,
            send_seq: 0,
            is_initiator: true,
        }
    }

    fn send_dir(&self) -> u8 {
        if self.is_initiator {
            DIR_SEND
        } else {
            DIR_RECV
        }
    }

    fn recv_dir(&self) -> u8 {
        if self.is_initiator {
            DIR_RECV
        } else {
            DIR_SEND
        }
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Establish a data-plane session from a 32-byte frame key.
    /// In production the key arrives from the Python PQ handshake
    /// (ML-KEM-1024 decapsulated secret via HKDF); it is copied into
    /// Rust memory here and zeroized. Python callers MUST pass a mutable
    /// bytearray and invoke DoD/zeroize wiping on their copy immediately after.
    /// `start_seq` SHOULD be a fresh 64-bit random offset per session.
    /// `is_initiator` MUST be true on exactly one side: it separates the
    /// two directions into distinct nonce domains (see `send_dir`).
    pub fn establish_session(
        &mut self,
        mut key_bytes: Vec<u8>,
        start_seq: u64,
        is_initiator: bool,
    ) -> PyResult<()> {
        if key_bytes.len() != 32 {
            return Err(PyValueError::new_err("frame key must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        use zeroize::Zeroize;
        key_bytes.zeroize();
        self.key = Some(FrameKey::from_bytes(arr));
        arr.zeroize();
        self.send_seq = start_seq;
        self.is_initiator = is_initiator;
        self.is_connected = true;
        Ok(())
    }

    /// Seal + pad one outbound message into a fixed-quantum wire frame.
    /// Returns (quantum, frame_bytes). Caller sends exactly quantum bytes.
    pub fn seal_msg(&mut self, ftype: u8, payload: Vec<u8>) -> PyResult<(usize, Vec<u8>)> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("no session: call establish_session first"))?;
        if ftype != FTYPE_MSG && ftype != FTYPE_CHAFF {
            return Err(PyValueError::new_err("unknown frame type"));
        }
        let (quantum, _pad) = pad_to_quantum(payload.len())
            .ok_or_else(|| PyValueError::new_err("payload exceeds largest quantum (1205B)"))?;
        let true_len = payload.len();
        let mut padded = payload;
        padded.resize(quantum - crate::frame::FRAME_OVERHEAD, 0u8);
        // Header length = TRUE length; open() strips padding. Wire size is
        // always exactly `quantum`, independent of content.
        let frame = aead::seal_with_len(
            key,
            self.send_seq,
            self.send_dir(),
            ftype,
            true_len as u16,
            &padded,
        )
        .map_err(|e| PyValueError::new_err(format!("seal failed: {e:?}")))?;
        self.send_seq = self.send_seq.wrapping_add(1);
        Ok((quantum, frame))
    }

    /// Open an inbound wire frame. Returns (ftype, payload-padded-bytes) or
    /// None when the frame must be dropped silently (bad tag / replay /
    /// behind-window). NEVER signal the peer on None.
    ///
    /// Split discipline (RFC 6479 / WireGuard Sec 5.4): read-only `check`
    /// on the unauthenticated peeked seq, then AEAD authentication, then
    /// `mark` ONLY on success. Forged seq never shifts state before auth.
    pub fn open_msg(&mut self, frame: Vec<u8>) -> Option<(u8, Vec<u8>)> {
        let key = self.key.as_ref()?;
        // Step 1: read-only check on unauthenticated header (no mutation).
        let peeked = aead::peek_seq(key, &frame)?;
        if !self.replay.check(peeked) {
            self.replay.note_drop();
            return None;
        }
        // Step 2: authenticate (seq bound via nonce + AAD header).
        let (seq, ftype, pt) = aead::open_indexed(key, self.recv_dir(), &frame).ok()?;
        if seq != peeked {
            return None;
        }
        // Step 3: mutate window ONLY on authentication success.
        self.replay.mark(seq);
        Some((ftype, pt))
    }

    /// Offer an inbound sequence number to the replay filter.
    /// Returns true = accept, false = drop silently (caller must not reply).
    /// NON-WIRE atomic helper retained for tests; wire paths MUST use
    /// `check_seq_readonly` then AEAD then `mark_seq` (see `open_msg`).
    pub fn check_seq(&mut self, seq: u64) -> bool {
        self.replay.check_and_update(seq)
    }

    /// Read-only acceptance test for unauthenticated input. No mutation.
    /// Wire pre-filter: call this, then authenticate, then `mark_seq`.
    pub fn check_seq_readonly(&self, seq: u64) -> bool {
        self.replay.check(seq)
    }

    /// Advance window for a validated seq. Call ONLY after
    /// `check_seq_readonly` accepted AND the AEAD tag verified.
    pub fn mark_seq(&mut self, seq: u64) {
        self.replay.mark(seq)
    }

    pub fn drop_count(&self) -> u64 {
        self.replay.drop_count()
    }
}

/// Native Hybrid Key Exchange (X25519 + ML-KEM-1024) exposed to Python.
/// Ephemeral private keys and raw shared secrets remain sealed and zeroized in Rust memory.
#[pyclass]
pub struct NativeHybridKex {
    keys: Option<kem::EphemeralKeys>,
}

#[pymethods]
impl NativeHybridKex {
    #[new]
    pub fn new() -> PyResult<Self> {
        let keys = kem::EphemeralKeys::generate()
            .map_err(|e| PyValueError::new_err(format!("KEX keygen failed: {e:?}")))?;
        Ok(NativeHybridKex { keys: Some(keys) })
    }

    /// Return our ephemeral public keys: (x25519_pub_32B, mlkem1024_ek_1568B).
    pub fn get_public_keys(&self) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("keys already consumed"))?;
        Ok((keys.x_public.to_vec(), keys.ml_ek.clone()))
    }

    /// Responder encapsulation: encapsulate against peer's (x_pub, ml_ek).
    /// Returns (eph_x_pub_32B, ml_ct_1568B, session_key_32B).
    #[staticmethod]
    pub fn encapsulate_to_peer(
        peer_x_pub: Vec<u8>,
        peer_ml_ek: Vec<u8>,
        transcript_hash: Vec<u8>,
    ) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        if peer_x_pub.len() != 32 {
            return Err(PyValueError::new_err("peer_x_pub must be 32 bytes"));
        }
        if peer_ml_ek.len() != kem::MLKEM_PK {
            return Err(PyValueError::new_err(format!(
                "peer_ml_ek must be {} bytes, got {}",
                kem::MLKEM_PK,
                peer_ml_ek.len()
            )));
        }
        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(&peer_x_pub);
        let (ct, hybrid_ss, eph_pub) = kem::EphemeralKeys::encapsulate(&x_arr, &peer_ml_ek)
            .map_err(|e| PyValueError::new_err(format!("encapsulate failed: {e:?}")))?;

        let session_key = if transcript_hash.len() == 48 {
            let mut th = [0u8; 48];
            th.copy_from_slice(&transcript_hash);
            kem::derive_session_key_transcript(&hybrid_ss, None, &th)
        } else {
            kem::derive_session_key(&hybrid_ss, b"ST2027-SESSION-KEY-V1")
        };
        Ok((eph_pub.to_vec(), ct, session_key.to_vec()))
    }

    /// Initiator decapsulation: decapsulate peer's (eph_x_pub, ml_ct) and derive 32B session key.
    pub fn decapsulate_session_key(
        &mut self,
        peer_eph_x_pub: Vec<u8>,
        peer_ml_ct: Vec<u8>,
        transcript_hash: Vec<u8>,
    ) -> PyResult<Vec<u8>> {
        let keys = self
            .keys
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("keys already consumed"))?;
        if peer_eph_x_pub.len() != 32 {
            return Err(PyValueError::new_err("peer_eph_x_pub must be 32 bytes"));
        }
        if peer_ml_ct.len() != kem::MLKEM_CT {
            return Err(PyValueError::new_err(format!(
                "peer_ml_ct must be {} bytes, got {}",
                kem::MLKEM_CT,
                peer_ml_ct.len()
            )));
        }
        let mut x_arr = [0u8; 32];
        x_arr.copy_from_slice(&peer_eph_x_pub);
        let hybrid_ss = keys
            .decapsulate(&x_arr, &peer_ml_ct)
            .map_err(|e| PyValueError::new_err(format!("decapsulate failed: {e:?}")))?;

        let session_key = if transcript_hash.len() == 48 {
            let mut th = [0u8; 48];
            th.copy_from_slice(&transcript_hash);
            kem::derive_session_key_transcript(&hybrid_ss, None, &th)
        } else {
            kem::derive_session_key(&hybrid_ss, b"ST2027-SESSION-KEY-V1")
        };
        Ok(session_key.to_vec())
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SecureEngine>()?;
    m.add_class::<NativeHybridKex>()?;
    ffi::register(m)?;
    Ok(())
}
