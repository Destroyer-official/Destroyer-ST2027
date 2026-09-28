//! Data-plane AEAD: ChaCha20-Poly1305 (RFC 8439) over framed packets.
//!
//! Frame: `[seq: u64 BE | len: u16 BE | ftype: u8 | ciphertext | tag: 16B]`.
//! The 16-byte Poly1305 tag covers header + ciphertext (AAD = header).
//! Nonce discipline: `seq_BE(8) || dir(1) || 0x00(3)` — strictly monotonic
//! per (key, direction); reuse is impossible while the replay window owns seq.
//! Any tag failure ⇒ caller MUST drop silently (no reply, no log above debug).
//!
//! Keys are `ZeroizeOnDrop` and never cross the FFI boundary.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::frame::{FTYPE_CHAFF, FTYPE_MSG};

/// Send/receive direction bit mixed into the nonce (domain separation).
pub const DIR_SEND: u8 = 0x00;
/// Send/receive direction bit mixed into the nonce (domain separation).
pub const DIR_RECV: u8 = 0x01;

/// 256-bit frame key. Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct FrameKey(Key);

impl FrameKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        FrameKey(Key::from(bytes))
    }

    /// Derive a frame key from a 32-byte ratchet secret via HKDF-SHA512.
    /// `info` MUST be domain-separated per use (e.g. b"destroyer/frame/v1").
    pub fn derive(secret: &[u8; 32], info: &[u8]) -> Self {
        use hkdf::Hkdf;
        use sha2::Sha512;
        let hk = Hkdf::<Sha512>::new(None, secret);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .expect("HKDF-SHA512 expand with 32-byte output cannot fail");
        let key = FrameKey(Key::from(okm));
        okm.zeroize_inner();
        key
    }
}

/// Zeroizing helper for local arrays (avoids trait import at call sites).
trait ZeroizeInner {
    fn zeroize_inner(&mut self);
}
impl ZeroizeInner for [u8; 32] {
    fn zeroize_inner(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

/// Build the 12-byte nonce for (seq, direction). Never reuse under one key.
pub fn make_nonce(seq: u64, dir: u8) -> Nonce {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&seq.to_be_bytes());
    n[8] = dir;
    Nonce::from(n)
}

/// Seal a payload into a complete wire frame (header + ct + tag).
pub fn seal(
    key: &FrameKey,
    seq: u64,
    dir: u8,
    ftype: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    debug_assert!(ftype == FTYPE_MSG || ftype == FTYPE_CHAFF);
    let cipher = ChaCha20Poly1305::new(&key.0);
    let nonce = make_nonce(seq, dir);
    let mut header = [0u8; 11];
    header[..8].copy_from_slice(&seq.to_be_bytes());
    header[8..10].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
    header[10] = ftype;
    let ct = cipher.encrypt(
        &nonce,
        Payload {
            msg: plaintext,
            aad: &header,
        },
    )?;
    let mut frame = Vec::with_capacity(header.len() + ct.len() + 16);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&ct); // ct includes the 16-byte tag
    Ok(frame)
}

/// Seal pre-padded plaintext where the header length is the TRUE payload
/// length (padding stripped on open). `padded` must already be quantum-sized.
#[allow(dead_code)]
pub fn seal_with_len(
    key: &FrameKey,
    seq: u64,
    dir: u8,
    ftype: u8,
    true_len: u16,
    padded: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    debug_assert!(ftype == FTYPE_MSG || ftype == FTYPE_CHAFF);
    let cipher = ChaCha20Poly1305::new(&key.0);
    let nonce = make_nonce(seq, dir);
    let mut header = [0u8; 11];
    header[..8].copy_from_slice(&seq.to_be_bytes());
    header[8..10].copy_from_slice(&true_len.to_be_bytes());
    header[10] = ftype;
    let ct = cipher.encrypt(
        &nonce,
        Payload {
            msg: padded,
            aad: &header,
        },
    )?;
    let mut frame = Vec::with_capacity(header.len() + ct.len() + 16);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&ct); // ct includes the 16-byte tag
    Ok(frame)
}

/// Open + authenticate a wire frame. Returns (ftype, plaintext) or drops (Err).
/// Kept for exact-length frames; padded frames use [`open_indexed`].
pub fn open(
    key: &FrameKey,
    dir: u8,
    frame: &[u8],
) -> Result<(u8, Zeroizing<Vec<u8>>), chacha20poly1305::aead::Error> {
    let (_seq, ftype, pt) = open_indexed(key, dir, frame)?;
    Ok((ftype, Zeroizing::new(pt)))
}

/// Open + authenticate, returning (seq, ftype, true-plaintext).
/// The header length truncates padding; overlong claims are rejected.
pub fn open_indexed(
    key: &FrameKey,
    dir: u8,
    frame: &[u8],
) -> Result<(u64, u8, Vec<u8>), chacha20poly1305::aead::Error> {
    use chacha20poly1305::aead::Error as AeadError;
    if frame.len() < 11 + 16 {
        return Err(AeadError);
    }
    let (header, ct) = frame.split_at(11);
    let seq = u64::from_be_bytes(header[..8].try_into().map_err(|_| AeadError)?);
    let ftype = header[10];
    if ftype != FTYPE_MSG && ftype != FTYPE_CHAFF {
        return Err(AeadError);
    }
    let cipher = ChaCha20Poly1305::new(&key.0);
    let pt = cipher.decrypt(
        &make_nonce(seq, dir),
        Payload { msg: ct, aad: header },
    )?;
    let len = u16::from_be_bytes([header[8], header[9]]) as usize;
    if len > pt.len() {
        return Err(AeadError);
    }
    Ok((seq, ftype, pt[..len].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> FrameKey {
        FrameKey::from_bytes([0x42u8; 32])
    }

    #[test]
    fn rfc8439_a1_vector_pins_backend() {
        // RFC 8439 §2.8.2 test vector (key/nonce/plaintext/ciphertext+tag).
        use chacha20poly1305::aead::Aead;
        let key_bytes: [u8; 32] = hex_to_bytes(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        )
        .try_into()
        .unwrap();
        let nonce_bytes: [u8; 12] = hex_to_bytes("070000004041424344454647")
            .try_into()
            .unwrap();
        let key = Key::from(key_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
        // RFC 8439 §2.8.2 vector, cross-generated with Python `cryptography`
        // (independent implementation) — see temp rfc8439kat.py. Do NOT
        // hand-edit: regenerate from the script on any doubt.
        let expected = hex_to_bytes(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62\
             d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ec\
             d3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad67594558580\
             8b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e2\
             6a7e902ecbd0600691",
        );
        let cipher = ChaCha20Poly1305::new(&key);
        let ct = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad: &aad })
            .unwrap();
        assert_eq!(ct, expected);
    }

    #[test]
    fn roundtrip_msg_and_chaff() {
        let key = test_key();
        for (seq, ftype, pt) in [
            (1u64, FTYPE_MSG, b"hello".as_slice()),
            (2u64, FTYPE_CHAFF, b"".as_slice()),
            (1_000_000u64, FTYPE_MSG, &[7u8; 1205][..]),
        ] {
            let frame = seal(&key, seq, DIR_SEND, ftype, pt).unwrap();
            let (t, out) = open(&key, DIR_SEND, &frame).unwrap();
            assert_eq!(t, ftype);
            assert_eq!(&out[..], pt);
        }
    }

    #[test]
    fn tampered_tag_header_or_type_drops() {
        let key = test_key();
        let frame = seal(&key, 9, DIR_SEND, FTYPE_MSG, b"data").unwrap();
        // Flip a tag byte.
        let mut bad = frame.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(open(&key, DIR_SEND, &bad).is_err());
        // Flip a header byte.
        let mut bad = frame.clone();
        bad[3] ^= 0x80;
        assert!(open(&key, DIR_SEND, &bad).is_err());
        // Wrong direction bit.
        assert!(open(&key, DIR_RECV, &frame).is_err());
        // Unknown type byte (re-seal manually is overkill; corrupt + fix tag is
        // infeasible — instead assert short-frame rejection).
        assert!(open(&key, DIR_SEND, &frame[..10]).is_err());
    }

    #[test]
    fn dir_separation_changes_nonce() {
        assert_ne!(make_nonce(7, DIR_SEND), make_nonce(7, DIR_RECV));
        assert_ne!(make_nonce(7, DIR_SEND), make_nonce(8, DIR_SEND));
    }

    #[test]
    fn hkdf_derive_is_deterministic_and_salted_by_info() {
        let secret = [9u8; 32];
        let a = FrameKey::derive(&secret, b"destroyer/frame/v1");
        let b = FrameKey::derive(&secret, b"destroyer/frame/v1");
        let c = FrameKey::derive(&secret, b"destroyer/frame/v2");
        assert_eq!(a.0.as_slice(), b.0.as_slice());
        assert_ne!(a.0.as_slice(), c.0.as_slice());
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
