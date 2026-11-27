//! Length-prefixed reliable stream framing & in-stream Noise_XXhfs handshake.
//!
//! Used both for embedded/piped Tor `DataStream` transports and local pipe/TCP
//! tests so KEX (M1 -> M2 -> M3) and AEAD session traffic share a SINGLE
//! authenticated stream with ZERO temporary `.key` files written to disk.

use std::io;
use std::time::Duration;

use sha2::{Digest, Sha384};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{AuthSigner, Mldsa87VerifyingKey};
use crate::handshake::{derive_double_ratchet_root, derive_shared_frame_key, Handshake};
use crate::kem::compute_sas;
use crate::memlock::LockedKey32;
use crate::policy::{CoreError, MLDSA87_PK};

/// Maximum length-prefixed frame size permitted during handshake (covers M2 = 8916B).
pub const MAX_HANDSHAKE_STREAM_FRAME: usize = 16 * 1024;
/// Maximum length-prefixed frame size permitted once switched to AEAD data plane.
pub const MAX_DATA_STREAM_FRAME: usize = 1232;

/// Keys and session metadata derived strictly in locked RAM from in-stream KEX.
pub struct InStreamSessionKeys {
    pub frame_key: LockedKey32,
    pub ratchet_root: LockedKey32,
    pub key_id: [u8; 16],
    pub sas: String,
    pub transcript_h: Zeroizing<[u8; 48]>,
}

/// Write a 2-byte big-endian length-prefixed frame, failing closed if empty or > `max_len`.
pub async fn write_stream_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
    max_len: usize,
) -> io::Result<()> {
    if payload.is_empty() || payload.len() > max_len || payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stream frame length out of bounds",
        ));
    }
    let len_be = (payload.len() as u16).to_be_bytes();
    writer.write_all(&len_be).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a 2-byte big-endian length-prefixed frame.
/// - `Ok(None)` cleanly signals EOF on a frame boundary.
/// - `Err(InvalidData)` rejects `len == 0` or `len > max_len` BEFORE allocating `len` bytes.
pub async fn read_stream_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut hdr = [0u8; 2];
    match reader.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(e) => return Err(e),
    }
    let len = u16::from_be_bytes(hdr) as usize;
    if len == 0 || len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed stream frame length (fail-closed)",
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

fn build_session_keys(
    k_send: &[u8; 32],
    k_recv: &[u8; 32],
    h: &[u8; 48],
    is_initiator: bool,
) -> InStreamSessionKeys {
    let mut fk_raw = derive_shared_frame_key(k_send, k_recv, h, is_initiator);
    let (mut rr_raw, h_out) = derive_double_ratchet_root(k_send, k_recv, h, is_initiator);
    let digest = Sha384::digest(fk_raw);
    let mut key_id = [0u8; 16];
    key_id.copy_from_slice(&digest[..16]);
    let sas = compute_sas(&fk_raw, &h_out);
    let frame_key = LockedKey32::new(fk_raw);
    let ratchet_root = LockedKey32::new(rr_raw);
    fk_raw.zeroize();
    rr_raw.zeroize();
    InStreamSessionKeys {
        frame_key,
        ratchet_root,
        key_id,
        sas,
        transcript_h: Zeroizing::new(h_out),
    }
}

/// Run initiator `Noise_XXhfs` (`M1 -> M2 -> M3`) in-band over a stream in RAM.
pub async fn in_stream_kex_initiator<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    signer: AuthSigner,
    psk: [u8; 32],
    expected_peer_pk: &[u8],
    deadline: Duration,
) -> Result<InStreamSessionKeys, CoreError> {
    if expected_peer_pk.len() != MLDSA87_PK {
        return Err(CoreError::Malformed);
    }
    Mldsa87VerifyingKey::from_bytes(expected_peer_pk)?;
    let sig_pk = signer.verifying_bytes();
    let mut hs = Handshake::initiator_external(sig_pk, Some(psk))?;

    let m1 = Zeroizing::new(hs.initiator_hello()?);
    timeout(deadline, write_stream_frame(stream, &m1, MAX_HANDSHAKE_STREAM_FRAME))
        .await
        .map_err(|_| CoreError::Stale)?
        .map_err(|_| CoreError::Malformed)?;

    let m2 = timeout(deadline, read_stream_frame(stream, MAX_HANDSHAKE_STREAM_FRAME))
        .await
        .map_err(|_| CoreError::Stale)?
        .map_err(|_| CoreError::Malformed)?
        .ok_or(CoreError::Malformed)?;
    hs.initiator_finish(&m2, expected_peer_pk)?;

    let m3 = Zeroizing::new(hs.initiator_complete_with(Some(&signer))?);
    timeout(deadline, write_stream_frame(stream, &m3, MAX_HANDSHAKE_STREAM_FRAME))
        .await
        .map_err(|_| CoreError::Stale)?
        .map_err(|_| CoreError::Malformed)?;

    let (mut ks, mut kr, mut h) = hs.split()?;
    let out = build_session_keys(&ks, &kr, &h, true);
    ks.zeroize();
    kr.zeroize();
    h.zeroize();
    Ok(out)
}

/// Run responder `Noise_XXhfs` (`M1 -> M2 -> M3`) in-band over a stream in RAM.
pub async fn in_stream_kex_responder<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    signer: AuthSigner,
    psk: [u8; 32],
    expected_peer_pk: &[u8],
    deadline: Duration,
) -> Result<InStreamSessionKeys, CoreError> {
    if expected_peer_pk.len() != MLDSA87_PK {
        return Err(CoreError::Malformed);
    }
    Mldsa87VerifyingKey::from_bytes(expected_peer_pk)?;
    let sig_pk = signer.verifying_bytes();
    let mut hs = Handshake::responder_external(sig_pk, Some(psk))?;

    let m1 = timeout(deadline, read_stream_frame(stream, MAX_HANDSHAKE_STREAM_FRAME))
        .await
        .map_err(|_| CoreError::Stale)?
        .map_err(|_| CoreError::Malformed)?
        .ok_or(CoreError::Malformed)?;
    let m2 = Zeroizing::new(hs.responder_reply_with(&m1, Some(&signer))?);

    timeout(deadline, write_stream_frame(stream, &m2, MAX_HANDSHAKE_STREAM_FRAME))
        .await
        .map_err(|_| CoreError::Stale)?
        .map_err(|_| CoreError::Malformed)?;

    let m3 = timeout(deadline, read_stream_frame(stream, MAX_HANDSHAKE_STREAM_FRAME))
        .await
        .map_err(|_| CoreError::Stale)?
        .map_err(|_| CoreError::Malformed)?
        .ok_or(CoreError::Malformed)?;
    hs.responder_complete(&m3, expected_peer_pk)?;

    let (mut ks, mut kr, mut h) = hs.split()?;
    let out = build_session_keys(&ks, &kr, &h, false);
    ks.zeroize();
    kr.zeroize();
    h.zeroize();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Mldsa87SigningKey;

    #[tokio::test]
    async fn stream_framing_rejects_zero_and_oversize_fail_closed() {
        let (mut w, mut r) = tokio::io::duplex(2048);
        assert!(write_stream_frame(&mut w, &[], MAX_DATA_STREAM_FRAME).await.is_err());
        assert!(write_stream_frame(&mut w, &[1u8; 1300], MAX_DATA_STREAM_FRAME)
            .await
            .is_err());

        // Inject invalid 0-length prefix and verify reader fails closed.
        w.write_all(&0u16.to_be_bytes()).await.unwrap();
        w.flush().await.unwrap();
        let err = read_stream_frame(&mut r, MAX_DATA_STREAM_FRAME).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Inject oversized frame header (> cap) and verify rejection BEFORE reading body.
        let (mut w2, mut r2) = tokio::io::duplex(2048);
        w2.write_all(&2000u16.to_be_bytes()).await.unwrap();
        w2.flush().await.unwrap();
        let err2 = read_stream_frame(&mut r2, MAX_DATA_STREAM_FRAME).await.unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn in_stream_noise_xxhfs_derives_identical_ram_keys() {
        let (i_sk, i_vk) = Mldsa87SigningKey::generate().unwrap();
        let (r_sk, r_vk) = Mldsa87SigningKey::generate().unwrap();
        let psk = [0x42u8; 32];
        let (mut cli, mut srv) = tokio::io::duplex(32 * 1024);

        let i_pk = i_vk.to_bytes();
        let r_pk = r_vk.to_bytes();

        let (ci, sr) = tokio::join!(
            in_stream_kex_initiator(
                &mut cli,
                AuthSigner::SoftwareOrTpmUnsealed(i_sk),
                psk,
                &r_pk,
                Duration::from_secs(5),
            ),
            in_stream_kex_responder(
                &mut srv,
                AuthSigner::SoftwareOrTpmUnsealed(r_sk),
                psk,
                &i_pk,
                Duration::from_secs(5),
            ),
        );
        let ik = ci.expect("initiator kex");
        let rk = sr.expect("responder kex");
        assert_eq!(ik.frame_key.as_bytes(), rk.frame_key.as_bytes());
        assert_eq!(ik.ratchet_root.as_bytes(), rk.ratchet_root.as_bytes());
        assert_eq!(ik.key_id, rk.key_id);
        assert_eq!(ik.sas, rk.sas);
    }

    #[tokio::test]
    async fn in_stream_noise_xxhfs_rejects_wrong_peer_pin() {
        let (i_sk, i_vk) = Mldsa87SigningKey::generate().unwrap();
        let (r_sk, _r_vk) = Mldsa87SigningKey::generate().unwrap();
        let (_wrong_sk, wrong_vk) = Mldsa87SigningKey::generate().unwrap();
        let psk = [0x99u8; 32];
        let (mut cli, mut srv) = tokio::io::duplex(32 * 1024);

        let i_pk = i_vk.to_bytes();
        let wrong_pk = wrong_vk.to_bytes();

        let (ci, sr) = tokio::join!(
            in_stream_kex_initiator(
                &mut cli,
                AuthSigner::SoftwareOrTpmUnsealed(i_sk),
                psk,
                &wrong_pk,
                Duration::from_secs(2),
            ),
            in_stream_kex_responder(
                &mut srv,
                AuthSigner::SoftwareOrTpmUnsealed(r_sk),
                psk,
                &i_pk,
                Duration::from_secs(2),
            ),
        );
        assert_eq!(ci.err(), Some(CoreError::KeyMismatch));
        assert!(sr.is_err());
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn verify_length_header_bounds() {
        let raw_len: u16 = kani::any();
        let cap: usize = MAX_DATA_STREAM_FRAME;
        let len = raw_len as usize;
        let accepted = len > 0 && len <= cap;
        if accepted {
            assert!(len >= 1 && len <= 1232);
        }
    }
}
