//! destroyer_core — Rust data plane for direct-IPv6 P2P.
//!
//! Phase 1 scope: authenticated framing, 64-bit anti-replay window,
//! fixed-size padding budgets, chaff typing, silent-drop networking,
//! symmetric ratchet state. PQ handshake stays in the Python control plane
//! (audited liboqs path) until Rust PQ crates are audited.
//!
//! FFI discipline: bytes and counters cross the boundary; raw key material
//! never leaves Rust except inside sealed calls. All secrets ZeroizeOnDrop.

pub mod aead;
pub mod chaff;
pub mod ct;
pub mod frame;
pub mod kem;
pub mod net;
pub mod nostd_microcore;
pub mod pad;
pub mod replay;

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
        let key = self.key.as_ref().ok_or_else(|| {
            PyValueError::new_err("no session: call establish_session first")
        })?;
        if ftype != FTYPE_MSG && ftype != FTYPE_CHAFF {
            return Err(PyValueError::new_err("unknown frame type"));
        }
        let (quantum, _pad) =
            pad_to_quantum(payload.len()).ok_or_else(|| {
                PyValueError::new_err("payload exceeds largest quantum (1205B)")
            })?;
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
        let peeked = aead::peek_seq(&frame)?;
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

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SecureEngine>()?;
    Ok(())
}
