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
use crate::pacing::sample_poisson_interval;
use crate::policy::{CoreError, MLDSA87_PK};
use crate::shaper::is_valid_quantum;

/// Maximum length-prefixed frame size permitted during legacy unpaced handshake (covers M2 = 8916B).
pub const MAX_HANDSHAKE_STREAM_FRAME: usize = 16 * 1024;
/// Maximum length-prefixed frame size permitted once switched to AEAD data plane.
pub const MAX_DATA_STREAM_FRAME: usize = 1232;
/// Fixed header inside each constant-quantum paced KEX cell: `[total_len:u16 | seq_idx:u16 | chunk_len:u16]`.
pub const KEX_CELL_HDR_LEN: usize = 6;
/// Sentinel sequence index marking a CSPRNG cover cell inside a paced KEX phase.
pub const KEX_COVER_SEQ: u16 = u16::MAX;
/// Strict pre-auth anti-DoS cap on dummy cover cells accepted per paced KEX phase.
pub const MAX_KEX_COVER_CELLS: usize = 256;

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
///
/// NOTE: NOT cancel-safe across partial reads (`read_exact`); callers using `tokio::select!`
/// MUST drive this on a dedicated split reader task (`tokio::io::split`) and select on an `mpsc` channel.
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

async fn pace_kex_tick(cell_interval: Duration, poisson: bool) -> Result<(), CoreError> {
    if cell_interval.is_zero() {
        return Ok(());
    }
    let delay = if poisson {
        let interval_ms = cell_interval.as_millis().clamp(1, 60_000) as u64;
        sample_poisson_interval(
            1000.0 / interval_ms as f64,
            Duration::from_millis(5),
            Duration::from_millis((interval_ms * 3).max(15)),
        )
        .map_err(|_| CoreError::Malformed)?
    } else {
        cell_interval
    };
    tokio::time::sleep(delay).await;
    Ok(())
}

/// Segment and transmit a handshake message (`M1`/`M2`/`M3`) exclusively as fixed-`quantum`
/// stream cells padded with randomly interleaved CSPRNG cover cells to a multiple of
/// `tamaraw_l` (capped at `MAX_KEX_COVER_CELLS` cover cells), always ending on the final real chunk.
async fn write_paced_kex_blob<W: AsyncWrite + Unpin>(
    writer: &mut W,
    blob: &[u8],
    quantum: usize,
    tamaraw_l: usize,
    cell_interval: Duration,
    poisson: bool,
) -> Result<(), CoreError> {
    if blob.is_empty() || blob.len() > MAX_HANDSHAKE_STREAM_FRAME || !is_valid_quantum(quantum) {
        return Err(CoreError::Malformed);
    }
    let payload_cap = quantum.saturating_sub(KEX_CELL_HDR_LEN);
    if payload_cap == 0 {
        return Err(CoreError::Malformed);
    }
    let n_real = blob.len().div_ceil(payload_cap);
    if n_real == 0 || n_real >= KEX_COVER_SEQ as usize {
        return Err(CoreError::Malformed);
    }

    let batch = tamaraw_l.clamp(1, 64);
    let target_cells = n_real.div_ceil(batch).saturating_mul(batch);
    let pad_cells = target_cells.saturating_sub(n_real).min(MAX_KEX_COVER_CELLS);
    let prefix_len = (n_real - 1) + pad_cells;

    // Place `pad_cells` cover slots and the first `n_real - 1` real chunks at CSPRNG-shuffled
    // positions while keeping real chunks strictly monotonic and ending deterministically on the last chunk.
    let mut is_real_slot = vec![false; prefix_len];
    for slot in is_real_slot.iter_mut().take(n_real - 1) {
        *slot = true;
    }
    for i in (1..is_real_slot.len()).rev() {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).map_err(|_| CoreError::Malformed)?;
        let j = (u64::from_le_bytes(r) as usize) % (i + 1);
        is_real_slot.swap(i, j);
    }
    is_real_slot.push(true);

    let mut next_chunk = 0usize;
    let mut cell = Zeroizing::new(vec![0u8; quantum]);
    for (idx, real) in is_real_slot.iter().copied().enumerate() {
        if idx > 0 {
            pace_kex_tick(cell_interval, poisson).await?;
        }
        getrandom::fill(cell.as_mut_slice()).map_err(|_| CoreError::Malformed)?;
        if real {
            let start = next_chunk * payload_cap;
            let end = ((next_chunk + 1) * payload_cap).min(blob.len());
            let chunk = &blob[start..end];
            cell[0..2].copy_from_slice(&(blob.len() as u16).to_be_bytes());
            cell[2..4].copy_from_slice(&(next_chunk as u16).to_be_bytes());
            cell[4..6].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
            cell[KEX_CELL_HDR_LEN..KEX_CELL_HDR_LEN + chunk.len()].copy_from_slice(chunk);
            next_chunk += 1;
        } else {
            cell[0..2].copy_from_slice(&0u16.to_be_bytes());
            cell[2..4].copy_from_slice(&KEX_COVER_SEQ.to_be_bytes());
            cell[4..6].copy_from_slice(&0u16.to_be_bytes());
        }
        write_stream_frame(writer, &cell, quantum)
            .await
            .map_err(|_| CoreError::Malformed)?;
    }
    Ok(())
}

/// Read and reassemble one handshake blob from fixed-`quantum` stream cells,
/// failing closed on any non-`quantum` frame, header mismatch, or cover flood.
async fn read_paced_kex_blob<R: AsyncRead + Unpin>(
    reader: &mut R,
    quantum: usize,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    if !is_valid_quantum(quantum) {
        return Err(CoreError::Malformed);
    }
    let payload_cap = quantum.saturating_sub(KEX_CELL_HDR_LEN);
    if payload_cap == 0 {
        return Err(CoreError::Malformed);
    }

    let mut cover_seen = 0usize;
    let mut expected_total: Option<usize> = None;
    let mut expected_chunks = 0usize;
    let mut next_seq = 0usize;
    let mut out = Zeroizing::new(Vec::new());

    loop {
        let mut frame = read_stream_frame(reader, quantum)
            .await
            .map_err(|_| CoreError::Malformed)?
            .ok_or(CoreError::Malformed)?;
        if frame.len() != quantum {
            frame.zeroize();
            return Err(CoreError::Malformed);
        }
        let total_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        let seq_idx = u16::from_be_bytes([frame[2], frame[3]]);
        let chunk_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;

        if seq_idx == KEX_COVER_SEQ {
            frame.zeroize();
            if total_len != 0 || chunk_len != 0 {
                return Err(CoreError::Malformed);
            }
            cover_seen += 1;
            if cover_seen > MAX_KEX_COVER_CELLS {
                return Err(CoreError::Malformed);
            }
            continue;
        }

        if total_len == 0 || total_len > MAX_HANDSHAKE_STREAM_FRAME {
            frame.zeroize();
            return Err(CoreError::Malformed);
        }

        let tot = match expected_total {
            Some(prev) if prev != total_len => {
                frame.zeroize();
                return Err(CoreError::Malformed);
            }
            Some(prev) => prev,
            None => {
                let chunks = total_len.div_ceil(payload_cap);
                if chunks == 0 || chunks >= KEX_COVER_SEQ as usize {
                    frame.zeroize();
                    return Err(CoreError::Malformed);
                }
                expected_chunks = chunks;
                expected_total = Some(total_len);
                out.reserve_exact(total_len);
                total_len
            }
        };

        if (seq_idx as usize) != next_seq || next_seq >= expected_chunks {
            frame.zeroize();
            return Err(CoreError::Malformed);
        }
        let expected_chunk = if next_seq + 1 < expected_chunks {
            payload_cap
        } else {
            tot - next_seq * payload_cap
        };
        if chunk_len == 0 || chunk_len != expected_chunk || KEX_CELL_HDR_LEN + chunk_len > frame.len() {
            frame.zeroize();
            return Err(CoreError::Malformed);
        }

        out.extend_from_slice(&frame[KEX_CELL_HDR_LEN..KEX_CELL_HDR_LEN + chunk_len]);
        frame.zeroize();
        next_seq += 1;
        if next_seq == expected_chunks {
            if out.len() != tot {
                return Err(CoreError::Malformed);
            }
            return Ok(out);
        }
    }
}

/// Configuration governing constant-quantum Tamaraw-paced in-stream handshake frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacedKexConfig {
    pub quantum: usize,
    pub tamaraw_l: usize,
    pub cell_interval: Duration,
    pub poisson: bool,
    pub deadline: Option<Duration>,
}

/// Run initiator `Noise_XXhfs` (`M1 -> M2 -> M3`) in RAM strictly over constant-`quantum`
/// paced cells so zero variable-size handshake bursts touch the wire.
pub async fn in_stream_kex_paced_initiator<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    signer: AuthSigner,
    psk: [u8; 32],
    expected_peer_pk: &[u8],
    cfg: PacedKexConfig,
) -> Result<InStreamSessionKeys, CoreError> {
    if expected_peer_pk.len() != MLDSA87_PK || !is_valid_quantum(cfg.quantum) {
        return Err(CoreError::Malformed);
    }
    Mldsa87VerifyingKey::from_bytes(expected_peer_pk)?;
    let sig_pk = signer.verifying_bytes();
    let mut hs = Handshake::initiator_external(sig_pk, Some(psk))?;

    let kex_fut = async {
        let m1 = Zeroizing::new(hs.initiator_hello()?);
        write_paced_kex_blob(
            stream,
            &m1,
            cfg.quantum,
            cfg.tamaraw_l,
            cfg.cell_interval,
            cfg.poisson,
        )
        .await?;

        let m2 = read_paced_kex_blob(stream, cfg.quantum).await?;
        hs.initiator_finish(&m2, expected_peer_pk)?;

        let m3 = Zeroizing::new(hs.initiator_complete_with(Some(&signer))?);
        write_paced_kex_blob(
            stream,
            &m3,
            cfg.quantum,
            cfg.tamaraw_l,
            cfg.cell_interval,
            cfg.poisson,
        )
        .await?;

        let (mut ks, mut kr, mut h) = hs.split()?;
        let out = build_session_keys(&ks, &kr, &h, true);
        ks.zeroize();
        kr.zeroize();
        h.zeroize();
        Ok::<InStreamSessionKeys, CoreError>(out)
    };

    match cfg.deadline {
        Some(limit) => timeout(limit, kex_fut)
            .await
            .map_err(|_| CoreError::Stale)?,
        None => kex_fut.await,
    }
}

/// Run responder `Noise_XXhfs` (`M1 -> M2 -> M3`) in RAM strictly over constant-`quantum`
/// paced cells so zero variable-size handshake bursts touch the wire.
pub async fn in_stream_kex_paced_responder<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    signer: AuthSigner,
    psk: [u8; 32],
    expected_peer_pk: &[u8],
    cfg: PacedKexConfig,
) -> Result<InStreamSessionKeys, CoreError> {
    if expected_peer_pk.len() != MLDSA87_PK || !is_valid_quantum(cfg.quantum) {
        return Err(CoreError::Malformed);
    }
    Mldsa87VerifyingKey::from_bytes(expected_peer_pk)?;
    let sig_pk = signer.verifying_bytes();
    let mut hs = Handshake::responder_external(sig_pk, Some(psk))?;

    let kex_fut = async {
        let m1 = read_paced_kex_blob(stream, cfg.quantum).await?;
        let m2 = Zeroizing::new(hs.responder_reply_with(&m1, Some(&signer))?);
        write_paced_kex_blob(
            stream,
            &m2,
            cfg.quantum,
            cfg.tamaraw_l,
            cfg.cell_interval,
            cfg.poisson,
        )
        .await?;

        let m3 = read_paced_kex_blob(stream, cfg.quantum).await?;
        hs.responder_complete(&m3, expected_peer_pk)?;

        let (mut ks, mut kr, mut h) = hs.split()?;
        let out = build_session_keys(&ks, &kr, &h, false);
        ks.zeroize();
        kr.zeroize();
        h.zeroize();
        Ok::<InStreamSessionKeys, CoreError>(out)
    };

    match cfg.deadline {
        Some(limit) => timeout(limit, kex_fut)
            .await
            .map_err(|_| CoreError::Stale)?,
        None => kex_fut.await,
    }
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

    struct WireFrameTap {
        inner: tokio::io::DuplexStream,
        written_frame_lens: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
        write_buf: Vec<u8>,
    }

    impl WireFrameTap {
        fn new(inner: tokio::io::DuplexStream, log: std::sync::Arc<std::sync::Mutex<Vec<usize>>>) -> Self {
            Self {
                inner,
                written_frame_lens: log,
                write_buf: Vec::new(),
            }
        }
    }

    impl AsyncRead for WireFrameTap {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for WireFrameTap {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            let poll = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
            if let std::task::Poll::Ready(Ok(n)) = &poll {
                self.write_buf.extend_from_slice(&buf[..*n]);
                while self.write_buf.len() >= 2 {
                    let frame_len = u16::from_be_bytes([self.write_buf[0], self.write_buf[1]]) as usize;
                    if self.write_buf.len() < 2 + frame_len {
                        break;
                    }
                    self.written_frame_lens.lock().unwrap().push(frame_len);
                    self.write_buf.drain(..2 + frame_len);
                }
            }
            poll
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn paced_in_stream_kex_emits_only_constant_quantum_cells_and_tamaraw_multiples() {
        let (i_sk, i_vk) = Mldsa87SigningKey::generate().unwrap();
        let (r_sk, r_vk) = Mldsa87SigningKey::generate().unwrap();
        let psk = [0x37u8; 32];
        let (cli_raw, srv_raw) = tokio::io::duplex(64 * 1024);

        let cli_lens = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let srv_lens = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cli = WireFrameTap::new(cli_raw, cli_lens.clone());
        let mut srv = WireFrameTap::new(srv_raw, srv_lens.clone());

        let i_pk = i_vk.to_bytes();
        let r_pk = r_vk.to_bytes();

        let kex_cfg = PacedKexConfig {
            quantum: 496,
            tamaraw_l: 16,
            cell_interval: Duration::ZERO,
            poisson: false,
            deadline: Some(Duration::from_secs(5)),
        };
        let (ci, sr) = tokio::join!(
            in_stream_kex_paced_initiator(
                &mut cli,
                AuthSigner::SoftwareOrTpmUnsealed(i_sk),
                psk,
                &r_pk,
                kex_cfg,
            ),
            in_stream_kex_paced_responder(
                &mut srv,
                AuthSigner::SoftwareOrTpmUnsealed(r_sk),
                psk,
                &i_pk,
                kex_cfg,
            ),
        );
        let ik = ci.expect("paced initiator kex");
        let rk = sr.expect("paced responder kex");
        assert_eq!(ik.frame_key.as_bytes(), rk.frame_key.as_bytes());
        assert_eq!(ik.ratchet_root.as_bytes(), rk.ratchet_root.as_bytes());
        assert_eq!(ik.sas, rk.sas);

        let i_frames = cli_lens.lock().unwrap();
        let r_frames = srv_lens.lock().unwrap();
        assert!(!i_frames.is_empty());
        assert!(!r_frames.is_empty());
        // Zero variable-size 1665B / 8916B / 6000B bursts may appear on the wire: every cell is 496B.
        assert!(i_frames.iter().all(|&n| n == 496), "unexpected initiator KEX cell size: {i_frames:?}");
        assert!(r_frames.iter().all(|&n| n == 496), "unexpected responder KEX cell size: {r_frames:?}");
        // Both initiator (M1 + M3, each padded to multiple of L=16) and responder (M2 padded to multiple of L=16)
        // must emit exact multiples of batch L=16 cells.
        assert_eq!(i_frames.len() % 16, 0, "initiator cells not Tamaraw-aligned: {}", i_frames.len());
        assert_eq!(r_frames.len() % 16, 0, "responder cells not Tamaraw-aligned: {}", r_frames.len());
    }

    #[tokio::test]
    async fn paced_in_stream_kex_poisson_and_pin_mismatch_behave_correctly() {
        let (i_sk, i_vk) = Mldsa87SigningKey::generate().unwrap();
        let (r_sk, _r_vk) = Mldsa87SigningKey::generate().unwrap();
        let (_wrong_sk, wrong_vk) = Mldsa87SigningKey::generate().unwrap();
        let psk = [0xA5u8; 32];
        let (mut cli, mut srv) = tokio::io::duplex(64 * 1024);

        let i_pk = i_vk.to_bytes();
        let wrong_pk = wrong_vk.to_bytes();
        let kex_cfg = PacedKexConfig {
            quantum: 496,
            tamaraw_l: 8,
            cell_interval: Duration::from_millis(5),
            poisson: true,
            deadline: Some(Duration::from_secs(5)),
        };
        let (ci, sr) = tokio::join!(
            in_stream_kex_paced_initiator(
                &mut cli,
                AuthSigner::SoftwareOrTpmUnsealed(i_sk),
                psk,
                &wrong_pk,
                kex_cfg,
            ),
            in_stream_kex_paced_responder(
                &mut srv,
                AuthSigner::SoftwareOrTpmUnsealed(r_sk),
                psk,
                &i_pk,
                kex_cfg,
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
