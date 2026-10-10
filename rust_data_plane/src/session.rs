//! Post-handshake transport + session pipeline (Rust secure core).
//!
//! Byte-identical wire format to the Python reference
//! (`noise_pq.transport_send` / `transport_recv`):
//! ```text
//! send: seq = send_n + 1 (starts at 1); dir = 0xA5 initiator / 0x5A responder
//! wire  = u64BE(seq) || AES-GCM(k_send, nonce=seqBE||dir||0x000000, pt, aad="NPQ1")
//! recv: parse seq; replay check (read-only) -> AEAD verify -> mark (RFC 6479 /
//!       WireGuard Sec 5.4: forged seq never shifts state before auth)
//! ```
//! Limits mirrored: plaintext ≤ 16384 bytes, wire ≥ 25 bytes, seq < 2^64-1
//! (exhaustion demands re-handshake).
//!
//! LAYERING GUIDANCE (explicit tradeoff): this transport is byte-identical
//! to the Python reference, so its 8-byte sequence prefix and wire length
//! are observable — it exists for handshake-adjacent messaging and
//! Python-interop, NOT for metadata-sensitive bulk transit. Established
//! sessions carrying payloads belong on the data-plane frames (`aead.rs`:
//! quanta padding + tag-derived header masking, `peek_seq` key-gated).
//! Hiding length/count always requires the constant-rate `channel`/chaff
//! cover regardless of path.
//!
//! `EstablishedSession` is the pipeline glue: handshake Split keys +
//! transcript → transport pair + shared frame key (for `SecureEngine` /
//! the data-plane binary) + Double Ratchet root. It consumes the
//! byte-identical `handshake::derive_*` functions, so keys agree with the
//! Python reference bit-for-bit (proven by the live interop test).

use aes_gcm::{
    aead::{Aead, KeyInit, Nonce, Payload},
    Aes256Gcm,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::handshake::{derive_double_ratchet_root, derive_shared_frame_key, HASHLEN};
use crate::policy::CoreError;
use crate::replay::AntiReplayWindow;

/// Initiator direction byte (identical to `noise_pq.transport_send`).
pub const DIR_INITIATOR: u8 = 0xA5;
/// Responder direction byte.
pub const DIR_RESPONDER: u8 = 0x5A;
/// Transport AAD (identical to `noise_pq` `"NPQ1"`).
pub const TRANSPORT_AAD: &[u8] = b"NPQ1";
/// Maximum transport plaintext (mirrors the Python reference).
pub const MAX_TRANSPORT_PT: usize = 16384;
/// Minimum wire length: seq(8) + ≥1 byte ct + tag(16).
pub const MIN_WIRE_LEN: usize = 8 + 1 + 16;

fn transport_nonce(seq: u64, direction: u8) -> Nonce<Aes256Gcm> {
    let mut b = [0u8; 12];
    b[..8].copy_from_slice(&seq.to_be_bytes());
    b[8] = direction;
    Nonce::<Aes256Gcm>::from(b)
}

/// Bidirectional transport over post-split keys. Directions are pinned at
/// construction (initiator seals with 0xA5 / opens 0x5A and vice versa),
/// so a reflection attack cannot re-key the stream.
///
/// Keys wipe on drop (manual `Drop`: the replay window holds public
/// sequence metadata, not secrets, and is not wiped).
pub struct Transport {
    k_send: [u8; 32],
    k_recv: [u8; 32],
    send_dir: u8,
    recv_dir: u8,
    send_n: u64,
    window: AntiReplayWindow,
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Only key halves are secrets; the replay window is public sequence
// metadata and intentionally survives wiping (it is rebuilt per session).
impl Zeroize for Transport {
    fn zeroize(&mut self) {
        self.k_send.zeroize();
        self.k_recv.zeroize();
    }
}

impl Transport {
    /// Build from split keys. `is_initiator` selects direction bytes.
    pub fn new(k_send: [u8; 32], k_recv: [u8; 32], is_initiator: bool) -> Self {
        let (send_dir, recv_dir) = if is_initiator {
            (DIR_INITIATOR, DIR_RESPONDER)
        } else {
            (DIR_RESPONDER, DIR_INITIATOR)
        };
        Self {
            k_send,
            k_recv,
            send_dir,
            recv_dir,
            send_n: 0,
            window: AntiReplayWindow::new(),
        }
    }

    /// Seal one message. Sequence starts at 1 (mirrors `sess._send_n + 1`).
    /// Empty plaintext is refused: the Python reference would emit a 24-byte
    /// wire the peer's own `len(wire) < 8 + 1 + 16` gate then rejects, so
    /// empty sends are unreceivable by construction — failing here at the
    /// source is the fail-closed equivalent (documented deviation).
    pub fn send(&mut self, pt: &[u8]) -> Result<Vec<u8>, CoreError> {
        if pt.is_empty() || pt.len() > MAX_TRANSPORT_PT {
            return Err(CoreError::Oversize);
        }
        if self.send_n == u64::MAX {
            return Err(CoreError::Malformed);
        }
        let seq = self.send_n.wrapping_add(1);
        self.send_n = seq;
        let cipher = Aes256Gcm::new_from_slice(&self.k_send).map_err(|_| CoreError::Malformed)?;
        let ct = cipher
            .encrypt(
                &transport_nonce(seq, self.send_dir),
                Payload {
                    msg: pt,
                    aad: TRANSPORT_AAD,
                },
            )
            .map_err(|_| CoreError::Malformed)?;
        let mut wire = Vec::with_capacity(8 + ct.len());
        wire.extend_from_slice(&seq.to_be_bytes());
        wire.extend_from_slice(&ct);
        Ok(wire)
    }

    /// Open one wire message: replay check → AEAD verify → mark.
    pub fn recv(&mut self, wire: &[u8]) -> Result<Vec<u8>, CoreError> {
        if wire.len() < MIN_WIRE_LEN {
            return Err(CoreError::Malformed);
        }
        let mut sb = [0u8; 8];
        sb.copy_from_slice(&wire[..8]);
        let seq = u64::from_be_bytes(sb);
        // Step 1: read-only replay test (forged seq cannot shift state).
        if !self.window.check(seq) {
            return Err(CoreError::Malformed);
        }
        // Step 2: authenticate.
        let cipher = Aes256Gcm::new_from_slice(&self.k_recv).map_err(|_| CoreError::Malformed)?;
        let pt = cipher
            .decrypt(
                &transport_nonce(seq, self.recv_dir),
                Payload {
                    msg: &wire[8..],
                    aad: TRANSPORT_AAD,
                },
            )
            .map_err(|_| CoreError::BadSignature)?;
        // Step 3: mutate window ONLY on authentication success.
        self.window.mark(seq);
        Ok(pt)
    }
}

/// Fully established session: transport pair + shared frame key (for the
/// data-plane `SecureEngine` / `secure-transmit` binary) + ratchet root +
/// transcript hash (channel-binding export). All key halves wiped on drop.
#[derive(ZeroizeOnDrop)]
pub struct EstablishedSession {
    /// Transport keys in (send, recv) order for this role.
    pub transport: Transport,
    /// 32-byte frame key (`derive_shared_frame_key`, Python-identical).
    pub frame_key: [u8; 32],
    /// 32-byte Double Ratchet root (`derive_double_ratchet_root`).
    pub ratchet_root: [u8; 32],
    /// 48-byte transcript hash (channel binding).
    pub transcript: [u8; HASHLEN],
    /// Role (direction discipline).
    pub is_initiator: bool,
}

impl EstablishedSession {
    /// Build from handshake Split output. `k_a`/`k_b` are the raw
    /// `(k1, k2)` split pair in initiator order (k1 initiator→responder).
    pub fn from_split(k1: &[u8; 32], k2: &[u8; 32], h: &[u8; HASHLEN], is_initiator: bool) -> Self {
        let (k_send, k_recv) = if is_initiator { (*k1, *k2) } else { (*k2, *k1) };
        let frame_key = derive_shared_frame_key(&k_send, &k_recv, h, is_initiator);
        let (ratchet_root, transcript) =
            derive_double_ratchet_root(&k_send, &k_recv, h, is_initiator);
        Self {
            transport: Transport::new(k_send, k_recv, is_initiator),
            frame_key,
            ratchet_root,
            transcript,
            is_initiator,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Transport, Transport) {
        let ks = [0x11u8; 32];
        let kr = [0x22u8; 32];
        // Keys crossed by role, exactly as `EstablishedSession::from_split`
        // assigns them (A sends ks, B receives ks).
        (Transport::new(ks, kr, true), Transport::new(kr, ks, false))
    }

    #[test]
    fn transport_roundtrip_bidirectional() {
        let (mut a, mut b) = pair();
        let w1 = a.send(b"hello responder").unwrap();
        assert_eq!(&w1[..8], &1u64.to_be_bytes());
        assert_eq!(b.recv(&w1).unwrap(), b"hello responder");
        let w2 = b.send(b"hello initiator").unwrap();
        assert_eq!(a.recv(&w2).unwrap(), b"hello initiator");
        // Empty plaintext refused at the source (unreceivable per MIN_WIRE).
        assert_eq!(a.send(b"").unwrap_err(), CoreError::Oversize);
    }

    #[test]
    fn reflection_replay_tamper_fail_closed() {
        let (mut a, mut b) = pair();
        let w = a.send(b"msg").unwrap();
        // Reflection: sender cannot open its own message (wrong direction).
        assert!(a.recv(&w).is_err());
        assert!(b.recv(&w).is_ok());
        // Replay refused (window already marked, tag would verify).
        assert!(b.recv(&w).is_err());
        // Tampered ciphertext refused; window NOT shifted by the forgery:
        // a subsequent honest message with a higher seq still opens.
        let mut w2 = a.send(b"msg2").unwrap();
        let last = w2.len() - 1;
        w2[last] ^= 1;
        assert!(b.recv(&w2).is_err());
        let w3 = a.send(b"msg3").unwrap();
        assert_eq!(b.recv(&w3).unwrap(), b"msg3");
        // Oversize + truncated refused.
        assert!(a.send(&vec![0u8; MAX_TRANSPORT_PT + 1]).is_err());
        assert!(b.recv(&[0u8; 10]).is_err());
    }

    #[test]
    fn pipeline_derives_role_crossed_keys() {
        let k1 = [0x33u8; 32];
        let k2 = [0x44u8; 32];
        let h = [0x55u8; HASHLEN];
        let ai = EstablishedSession::from_split(&k1, &k2, &h, true);
        let ar = EstablishedSession::from_split(&k1, &k2, &h, false);
        assert_eq!(ai.frame_key, ar.frame_key);
        assert_eq!(ai.ratchet_root, ar.ratchet_root);
        assert_eq!(ai.transcript, ar.transcript);
        assert_ne!(ai.frame_key, ai.ratchet_root); // domain-separated labels
    }
}
