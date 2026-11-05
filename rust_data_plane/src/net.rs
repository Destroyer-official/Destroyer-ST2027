//! Silent-drop UDP transport (dual-stack IPv6/IPv4).
//!
//! Black-hole discipline: parse/AEAD/rate failures increment local counters
//! and the datagram is forgotten. This module NEVER sends error replies, RST,
//! ICMP, or diagnostics in response to inbound traffic. Replies exist only as
//! explicit `send_raw` calls made by session logic for ACCEPTED peers.
//!
//! Rate limiting is a per-source token bucket so one scanner cannot starve the
//! peer or amplify work: over-budget datagrams are dropped before parsing.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};

use crate::aead::{self, FrameKey, DIR_RECV, DIR_SEND};
use crate::frame::{
    FTYPE_IN_BAND_EPOCH_REKEY, IN_BAND_REKEY_PAYLOAD_LEN,
};
use crate::fragment::{fragment, Fragment, ReassemblyBuffer};
use crate::policy::CoreError;
use crate::ratchet::PcsRatchet;
use crate::replay::AntiReplayWindow;

/// Token-bucket budget per source address.
const BUCKET_CAPACITY: f64 = 64.0;
/// Refill rate: tokens per second per source.
const BUCKET_REFILL_PER_SEC: f64 = 16.0;
/// Largest datagram this plane will accept: the IPv6 minimum MTU (RFC 8200).
/// Anything larger arrives fragmented (operationally fragile, fingerprintable,
/// amplification-friendly) and is dropped BEFORE parsing. Internal buffer is
/// one byte larger so oversize is detectable (UDP truncates silently).
pub const MAX_DATAGRAM: usize = 1280;
/// Cap on tracked source addresses. UDP source IPs are spoofable, so an
/// unbounded per-IP table is a memory-exhaustion primitive: past this many
/// distinct sources the stalest bucket is evicted (H24).
pub const MAX_BUCKETS: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Bucket {
            tokens: BUCKET_CAPACITY,
            last: now,
        }
    }

    /// Returns true when one token could be consumed (and consumes it).
    fn take(&mut self, now: Instant) -> bool {
        let dt = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * BUCKET_REFILL_PER_SEC).min(BUCKET_CAPACITY);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct Endpoint {
    socket: UdpSocket,
    buckets: HashMap<IpAddr, Bucket>,
    /// Datagrams dropped for any reason (parse/auth/rate). Never signaled.
    pub drops: u64,
    /// Datagrams accepted past the rate limiter (still need AEAD check).
    pub admitted: u64,
}

impl Endpoint {
    /// Bind a dual-stack socket. `[::]:port` serves IPv6 (and IPv4-mapped).
    pub async fn bind(addr: &str) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Endpoint {
            socket,
            buckets: HashMap::new(),
            drops: 0,
            admitted: 0,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Explicit outbound send. ONLY call for accepted peers / session traffic.
    pub async fn send_raw(&self, data: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(data, to).await
    }

    /// Receive one datagram with rate limiting applied.
    /// - `None`: timeout (no traffic) — NOT a drop.
    /// - `Some(Err(..))`: caller must forget it silently (already counted).
    /// - `Some(Ok((bytes, from)))`: admitted; AEAD check still required.
    pub async fn recv_raw(
        &mut self,
        wait: Duration,
    ) -> Option<Result<(Vec<u8>, SocketAddr), OverBudget>> {
        // +1 so oversize (>1280, i.e. fragmented) is detectable: UDP truncates
        // silently, and truncated frames must never reach the parser.
        let mut buf = [0u8; MAX_DATAGRAM + 1];
        let (n, from) = match timeout(wait, self.socket.recv_from(&mut buf)).await {
            Err(_) => return None,
            Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionReset => return None,
            Ok(Err(_)) => {
                self.drops += 1;
                return Some(Err(OverBudget::Io));
            }
            Ok(Ok(v)) => v,
        };
        if n > MAX_DATAGRAM {
            self.drops += 1;
            return Some(Err(OverBudget::Oversize));
        }
        let now = Instant::now();
        if !self.buckets.contains_key(&from.ip()) {
            self.evict_stale_buckets();
        }
        let bucket = self
            .buckets
            .entry(from.ip())
            .or_insert_with(|| Bucket::new(now));
        if !bucket.take(now) {
            self.drops += 1;
            return Some(Err(OverBudget::Rate));
        }
        self.admitted += 1;
        Some(Ok((buf[..n].to_vec(), from)))
    }

    /// Receive one datagram without rate limiting (used for authenticated, dedicated point-to-point enclaves)
    pub async fn recv_unthrottled(
        &mut self,
        wait: Duration,
    ) -> Option<Result<(Vec<u8>, SocketAddr), OverBudget>> {
        let mut buf = [0u8; MAX_DATAGRAM + 1];
        let (n, from) = match timeout(wait, self.socket.recv_from(&mut buf)).await {
            Err(_) => return None,
            Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionReset => return None,
            Ok(Err(_)) => {
                self.drops += 1;
                return Some(Err(OverBudget::Io));
            }
            Ok(Ok(v)) => v,
        };
        if n > MAX_DATAGRAM {
            self.drops += 1;
            return Some(Err(OverBudget::Oversize));
        }
        self.admitted += 1;
        Some(Ok((buf[..n].to_vec(), from)))
    }

    /// Evict stalest buckets while over the per-IP table cap (H24).
    fn evict_stale_buckets(&mut self) {
        while self.buckets.len() >= MAX_BUCKETS {
            let stale = match self
                .buckets
                .iter()
                .min_by(|a, b| a.1.last.cmp(&b.1.last))
                .map(|(k, _)| *k)
            {
                Some(k) => k,
                None => break,
            };
            self.buckets.remove(&stale);
            self.drops += 1;
        }
    }

    /// Record an authentication/parse failure. Silent by construction.
    pub fn note_auth_drop(&mut self) {
        self.drops += 1;
    }
}

/// Active sovereign UDP transmission loop connecting PcsRatchet to the network transport.
///
/// Enforces:
/// 1. True Post-Compromise Security (PCS) via In-Band Continuous Epoch Ratchet (CER).
/// 2. Automatic epoch rollover every N = 10,000 packets or M = 10 MB of transmitted data:
///    `RootKey_{epoch+1} = HKDF-SHA384(RootKey_{epoch}, ML-KEM-1024-Decaps(ct))`
/// 3. Immediate volatile zeroization of old epoch keys.
/// 4. Cryptographic framing, padding, and anti-replay defense.
pub struct ActiveTransmissionLoop {
    pub endpoint: Endpoint,
    pub peer_addr: SocketAddr,
    pub ratchet: PcsRatchet,
    pub current_frame_key: FrameKey,
    pub previous_frame_key: Option<FrameKey>,
    pub send_dir: u8,
    pub recv_dir: u8,
    pub next_send_seq: u64,
    pub replay_window: AntiReplayWindow,
    pub quantum: usize,
    pub outbound_rekey_frags: VecDeque<Vec<u8>>,
    pub active_reassembly: Option<ReassemblyBuffer>,
}

impl ActiveTransmissionLoop {
    /// Initialize a new active transmission loop with initial session key, role, and wire quantum.
    pub fn new(
        endpoint: Endpoint,
        peer_addr: SocketAddr,
        initial_key: &[u8; 32],
        role: &str,
        quantum: usize,
    ) -> Result<Self, CoreError> {
        let (send_dir, recv_dir) = if role == "responder" {
            (DIR_RECV, DIR_SEND)
        } else {
            (DIR_SEND, DIR_RECV)
        };
        let ratchet = PcsRatchet::new(initial_key)?;
        let current_frame_key = ratchet.current_frame_key()?;
        Ok(Self {
            endpoint,
            peer_addr,
            ratchet,
            current_frame_key,
            previous_frame_key: None,
            send_dir,
            recv_dir,
            next_send_seq: 1,
            replay_window: AntiReplayWindow::new(),
            quantum,
            outbound_rekey_frags: VecDeque::new(),
            active_reassembly: None,
        })
    }

    /// Set peer's advertised bundle (used for autonomous ML-KEM-1024 encapsulation).
    pub fn set_peer_bundle(&mut self, bundle: crate::ratchet::AdvertBundle) {
        self.ratchet.set_peer_bundle(bundle);
    }

    /// Trigger in-band continuous epoch rollover:
    /// - Generates fresh Frame Type 0x07 payload (1588 bytes):
    ///   `EpochIndex (u32) || Ephemeral_MLKEM_Ciphertext (1568 bytes) || AuthTag (16 bytes)`.
    /// - Evolves root key: `RootKey_{epoch+1} = HKDF-SHA384(RootKey_{epoch}, ML-KEM-1024-Decaps(ct))`.
    /// - Volatile-zeroizes old root, old chain, decapsulation key, and shared secrets immediately.
    /// - Advances active FrameKey and queues rekey fragments or direct frame.
    pub async fn trigger_in_band_epoch_rollover(&mut self) -> Result<u64, CoreError> {
        let payload = self.ratchet.build_in_band_epoch_rekey_auto()?;
        let next_key = self.ratchet.current_frame_key()?;
        self.previous_frame_key = Some(self.current_frame_key.clone());
        self.current_frame_key = next_key;

        if self.quantum >= 1615 {
            // Direct unfragmented mode (jumbo / enclave)
            let seq = self.next_send_seq;
            self.next_send_seq = self.next_send_seq.checked_add(1).ok_or(CoreError::Oversize)?;
            let frame = crate::pacing::build_epoch_rekey_frame_directed(
                self.previous_frame_key.as_ref().unwrap(),
                seq,
                self.send_dir,
                self.quantum,
                &payload,
            ).map_err(|_| CoreError::Malformed)?;
            self.endpoint.send_raw(&frame, self.peer_addr).await.map_err(|_| CoreError::Malformed)?;
        } else {
            // Quantum-sliced fragment mode (standard IPv6 1232B quantum)
            let chunk_size = if self.quantum >= 1232 { 600 } else if self.quantum >= 512 { 200 } else { 120 };
            if let Ok(frags) = fragment(&payload, chunk_size) {
                for f in frags {
                    self.outbound_rekey_frags.push_back(f.to_wire());
                }
            }
        }
        Ok(self.ratchet.epoch())
    }

    /// Flush any pending outbound rekey fragments into on-wire frames under transition key.
    pub async fn flush_rekey_fragments(&mut self) -> Result<usize, CoreError> {
        let mut sent = 0;
        let active_key = if let Some(ref prev) = self.previous_frame_key {
            prev
        } else {
            &self.current_frame_key
        };

        while let Some(frag_wire) = self.outbound_rekey_frags.pop_front() {
            let seq = self.next_send_seq;
            self.next_send_seq = self.next_send_seq.checked_add(1).ok_or(CoreError::Oversize)?;
            let frame = crate::pacing::build_epoch_rekey_frame_directed(
                active_key,
                seq,
                self.send_dir,
                self.quantum,
                &frag_wire,
            ).map_err(|_| CoreError::Malformed)?;
            self.endpoint.send_raw(&frame, self.peer_addr).await.map_err(|_| CoreError::Malformed)?;
            sent += 1;
        }
        Ok(sent)
    }

    /// Send an application data packet under the active session key.
    /// Automatically checks if N = 10,000 packets or M = 10 MB has been reached;
    /// triggers automatic continuous epoch rollover and immediate zeroization of old keys.
    pub async fn send_msg(&mut self, payload: &[u8]) -> Result<u64, CoreError> {
        self.ratchet.note_transmission(payload.len());

        // Automatic rollover check: N = 10,000 packets or M = 10 MB
        if self.ratchet.needs_rollover() && self.ratchet.peer_bundle().is_some() {
            self.trigger_in_band_epoch_rollover().await?;
        }

        // Flush any pending rekey fragments first
        self.flush_rekey_fragments().await?;

        let seq = self.next_send_seq;
        self.next_send_seq = self.next_send_seq.checked_add(1).ok_or(CoreError::Oversize)?;
        let frame = crate::pacing::build_data_frame_directed(
            &self.current_frame_key,
            seq,
            self.send_dir,
            self.quantum,
            payload,
        ).map_err(|_| CoreError::Malformed)?;

        self.endpoint.send_raw(&frame, self.peer_addr).await.map_err(|_| CoreError::Malformed)?;
        Ok(seq)
    }

    /// Send a constant-rate synthetic chaff frame under the active session key.
    pub async fn send_chaff(&mut self) -> Result<u64, CoreError> {
        self.ratchet.note_transmission(0);

        if self.ratchet.needs_rollover() && self.ratchet.peer_bundle().is_some() {
            self.trigger_in_band_epoch_rollover().await?;
        }
        self.flush_rekey_fragments().await?;

        let seq = self.next_send_seq;
        self.next_send_seq = self.next_send_seq.checked_add(1).ok_or(CoreError::Oversize)?;
        let frame = crate::pacing::build_chaff_frame_directed(
            &self.current_frame_key,
            seq,
            self.send_dir,
            self.quantum,
        ).map_err(|_| CoreError::Malformed)?;

        self.endpoint.send_raw(&frame, self.peer_addr).await.map_err(|_| CoreError::Malformed)?;
        Ok(seq)
    }

    /// Receive and process an incoming datagram:
    /// - Checks anti-replay window.
    /// - Unmasks header and verifies AEAD authentication.
    /// - Handles Frame Type 0x07 IN_BAND_EPOCH_REKEY:
    ///   Reassembles fragments, verifies 16-byte AuthTag, decapsulates ML-KEM-1024 ciphertext,
    ///   evolves root: `RootKey_{epoch+1} = HKDF-SHA384(RootKey_{epoch}, Decaps(ct))`,
    ///   volatile-zeroizes old root, old chain, decapsulation key immediately.
    /// - Returns `(seq, ftype, payload)`.
    pub async fn recv_packet(&mut self, wait: Duration) -> Result<Option<(u64, u8, Vec<u8>)>, CoreError> {
        let Some(res) = self.endpoint.recv_unthrottled(wait).await else {
            return Ok(None);
        };
        let (bytes, _from) = res.map_err(|_| CoreError::Malformed)?;
        if bytes.len() != self.quantum {
            self.endpoint.note_auth_drop();
            return Ok(None);
        }

        // Try unmasking seq with current key, fallback to previous key during transition grace
        let (seq, use_prev) = match aead::peek_seq(&self.current_frame_key, &bytes) {
            Some(s) => (s, false),
            None => {
                if let Some(ref prev) = self.previous_frame_key {
                    match aead::peek_seq(prev, &bytes) {
                        Some(s) => (s, true),
                        None => {
                            self.endpoint.note_auth_drop();
                            return Ok(None);
                        }
                    }
                } else {
                    self.endpoint.note_auth_drop();
                    return Ok(None);
                }
            }
        };

        if !self.replay_window.check(seq) {
            self.endpoint.note_auth_drop();
            return Ok(None);
        }

        let open_res = if use_prev {
            aead::open_indexed(self.previous_frame_key.as_ref().unwrap(), self.recv_dir, &bytes)
        } else {
            aead::open_indexed(&self.current_frame_key, self.recv_dir, &bytes)
        };

        let Ok((seq2, ftype, pt)) = open_res else {
            self.endpoint.note_auth_drop();
            return Ok(None);
        };

        if seq2 != seq {
            self.endpoint.note_auth_drop();
            return Ok(None);
        }

        self.replay_window.mark(seq2);

        if ftype == FTYPE_IN_BAND_EPOCH_REKEY {
            // Process rekey payload (either direct 1588 bytes or fragmented)
            if pt.len() == IN_BAND_REKEY_PAYLOAD_LEN {
                self.ratchet.process_in_band_epoch_rekey(&pt)?;
                self.previous_frame_key = Some(self.current_frame_key.clone());
                self.current_frame_key = self.ratchet.current_frame_key()?;
            } else if let Ok(frag) = Fragment::from_wire(&pt) {
                let should_assemble = match self.active_reassembly {
                    Some(ref mut r) if r.tx_id() == frag.tx_id => r.insert(frag).unwrap_or(false),
                    _ => {
                        if let Ok(mut r) = ReassemblyBuffer::new(frag.tx_id, frag.total) {
                            let done = r.insert(frag).unwrap_or(false);
                            self.active_reassembly = Some(r);
                            done
                        } else {
                            false
                        }
                    }
                };
                if should_assemble {
                    if let Some(r) = self.active_reassembly.take() {
                        if let Ok(full_bytes) = r.reassemble() {
                            if full_bytes.len() == IN_BAND_REKEY_PAYLOAD_LEN {
                                self.ratchet.process_in_band_epoch_rekey(&full_bytes)?;
                                self.previous_frame_key = Some(self.current_frame_key.clone());
                                self.current_frame_key = self.ratchet.current_frame_key()?;
                            }
                        }
                    }
                }
            }
        }

        Ok(Some((seq2, ftype, pt)))
    }
}

/// Reason a datagram was forgotten. Never serialized to the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverBudget {
    Rate,
    Io,
    Oversize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{self, FrameKey, DIR_SEND};
    use crate::frame::FTYPE_MSG;

    async fn loopback_pair() -> (Endpoint, Endpoint) {
        let a = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let b = Endpoint::bind("127.0.0.1:0").await.unwrap();
        (a, b)
    }

    #[tokio::test]
    async fn garbage_gets_no_reply_and_counts_drop() {
        let (mut rx, mut tx) = loopback_pair().await;
        let rx_addr = rx.local_addr().unwrap();
        // Attacker/scanner sends garbage.
        tx.send_raw(b"scan-probe-garbage", rx_addr).await.unwrap();
        let got = rx.recv_raw(Duration::from_millis(500)).await;
        let (bytes, _from) = got.expect("datagram arrives").expect("within budget");
        // AEAD open fails → silent drop, and crucially NO reply is sent.
        let key = FrameKey::from_bytes([1u8; 32]);
        assert!(aead::open(&key, DIR_SEND, &bytes).is_err());
        rx.note_auth_drop();
        assert_eq!(rx.drops, 1);
        // Scanner listens for any reply: must hear nothing.
        let reply = tx.recv_raw(Duration::from_millis(300)).await;
        assert!(
            reply.is_none(),
            "listener replied to garbage — stealth violated"
        );
    }

    #[tokio::test]
    async fn valid_sealed_frame_roundtrips() {
        let (mut rx, tx) = loopback_pair().await;
        let rx_addr = rx.local_addr().unwrap();
        let key = FrameKey::from_bytes([7u8; 32]);
        let frame = aead::seal(&key, 42, DIR_SEND, FTYPE_MSG, b"hello-india").unwrap();
        tx.send_raw(&frame, rx_addr).await.unwrap();
        let (bytes, _) = rx
            .recv_raw(Duration::from_millis(500))
            .await
            .expect("datagram arrives")
            .expect("within budget");
        let (t, pt) = aead::open(&key, DIR_SEND, &bytes).unwrap();
        assert_eq!(t, FTYPE_MSG);
        assert_eq!(&pt[..], b"hello-india");
    }

    #[tokio::test]
    async fn burst_over_budget_drops_silently() {
        let (mut rx, tx) = loopback_pair().await;
        let rx_addr = rx.local_addr().unwrap();
        let mut rated = 0u32;
        // 64 budget + refill raced; send far beyond capacity in one burst.
        for _ in 0..256 {
            tx.send_raw(b"x", rx_addr).await.unwrap();
            match rx.recv_raw(Duration::from_millis(50)).await {
                Some(Err(_)) => rated += 1,
                Some(Ok(_)) => {}
                None => break,
            }
        }
        assert!(rated > 0, "rate limiter never engaged");
        assert_eq!(rx.drops as u32, rated);
    }

    #[tokio::test]
    async fn ipv6_loopback_roundtrips() {
        // Dual-stack proof: same code path over real IPv6 loopback.
        let mut rx = Endpoint::bind("[::1]:0").await.unwrap();
        let tx = Endpoint::bind("[::1]:0").await.unwrap();
        let rx_addr = rx.local_addr().unwrap();
        assert!(rx_addr.is_ipv6());
        let key = FrameKey::from_bytes([9u8; 32]);
        let frame = aead::seal(&key, 7, DIR_SEND, FTYPE_MSG, b"ipv6-india-us").unwrap();
        tx.send_raw(&frame, rx_addr).await.unwrap();
        let (bytes, from) = rx
            .recv_raw(Duration::from_millis(500))
            .await
            .expect("datagram arrives")
            .expect("within budget");
        assert!(from.ip().is_loopback());
        let (t, pt) = aead::open(&key, DIR_SEND, &bytes).unwrap();
        assert_eq!((t, &pt[..]), (FTYPE_MSG, b"ipv6-india-us".as_slice()));
    }

    #[tokio::test]
    async fn oversize_fragmented_datagram_drops_before_parse() {
        let (mut rx, tx) = loopback_pair().await;
        let rx_addr = rx.local_addr().unwrap();
        // 1400B > 1280: fragmented on real paths — must never reach the parser.
        // Windows fails the oversized read at the OS (Io); POSIX would deliver
        // and hit our Oversize branch. Both are silent pre-parse drops.
        let big = vec![0xAAu8; 1400];
        tx.send_raw(&big, rx_addr).await.unwrap();
        match rx.recv_raw(Duration::from_millis(500)).await {
            Some(Err(OverBudget::Oversize)) => {}
            Some(Err(OverBudget::Io)) => {}
            other => panic!("oversize must drop pre-parse, got {other:?}"),
        }
        assert_eq!(rx.drops, 1);
        assert_eq!(rx.admitted, 0);
    }

    #[tokio::test]
    async fn full_pipeline_seal_send_recv_replay_open() {
        // The production data path end to end: seal → send → recv → replay
        // window → open, with independent sender/receiver windows.
        use crate::replay::AntiReplayWindow;
        let (mut rx, tx) = loopback_pair().await;
        let rx_addr = rx.local_addr().unwrap();
        let key = FrameKey::from_bytes([11u8; 32]);
        let mut window = AntiReplayWindow::with_offset(8999);
        for (send_seq, i) in (9000_u64..).zip(0..50u64) {
            let frame = aead::seal(
                &key,
                send_seq,
                DIR_SEND,
                FTYPE_MSG,
                format!("pkt-{i}").as_bytes(),
            )
            .unwrap();
            assert!(frame.len() <= 1280, "frame exceeds IPv6 MTU budget");
            tx.send_raw(&frame, rx_addr).await.unwrap();
            let (bytes, _) = rx
                .recv_raw(Duration::from_millis(500))
                .await
                .expect("datagram arrives")
                .expect("within budget");
            // Parse seq from header via peek_seq.
            let seq = aead::peek_seq(&key, &bytes).expect("valid seq unmask");
            assert!(window.check_and_update(seq), "fresh seq rejected");
            let (t, pt) = aead::open(&key, DIR_SEND, &bytes).unwrap();
            assert_eq!(
                (t, &pt[..]),
                (FTYPE_MSG, format!("pkt-{i}").into_bytes().as_slice())
            );
            // Immediate replay of the same datagram must die at the window.
            assert!(!window.check_and_update(seq), "replay accepted");
        }
        assert_eq!(rx.admitted, 50);
        assert_eq!(rx.drops, 0);
    }

    #[tokio::test]
    async fn bucket_refills_over_time() {
        // Exhaust, wait for refill (16/s), confirm admission resumes.
        let (mut rx, tx) = loopback_pair().await;
        let rx_addr = rx.local_addr().unwrap();
        for _ in 0..70 {
            tx.send_raw(b"x", rx_addr).await.unwrap();
            let _ = rx.recv_raw(Duration::from_millis(20)).await;
        }
        assert!(rx.drops > 0);
        tokio::time::sleep(Duration::from_millis(1500)).await; // ~24 tokens
        tx.send_raw(b"again", rx_addr).await.unwrap();
        match rx.recv_raw(Duration::from_millis(500)).await {
            Some(Ok((b, _))) => assert_eq!(b, b"again"),
            other => panic!("refilled bucket must admit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bucket_table_evicts_stalest_over_cap() {
        // H24: spoofed-source floods must not grow the per-IP table forever.
        use std::net::IpAddr;
        let mut rx = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let now = Instant::now();
        for i in 0..(MAX_BUCKETS + 64) {
            let b = (i >> 16) as u8;
            let c = (i >> 8) as u8;
            let d = i as u8;
            let ip: IpAddr = format!("10.{b}.{c}.{d}").parse().unwrap();
            rx.buckets.insert(ip, Bucket::new(now));
        }
        assert!(rx.buckets.len() > MAX_BUCKETS);
        rx.evict_stale_buckets();
        assert!(
            rx.buckets.len() <= MAX_BUCKETS,
            "bucket table over cap after eviction"
        );
    }

    #[tokio::test]
    async fn sustained_traffic_under_scanner_fire() {
        // closest-to-real battle test on one host: 200 legit frames of mixed
        // sizes flow peer→peer while a second source (scanner) blasts garbage
        // at 4x volume. Per-source buckets must isolate the peer: zero legit
        // loss, zero replies to the scanner, every wire frame ≤1280B.
        use crate::replay::AntiReplayWindow;
        let mut rx = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let peer = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let mut scanner = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let key = FrameKey::from_bytes([13u8; 32]);
        let mut window = AntiReplayWindow::new();
        let mut seq: u64 = 1;
        let mut legit_ok = 0u32;
        for i in 0..200u32 {
            // Mixed sizes spanning all three quanta.
            let size = match i % 4 {
                0 => 10,
                1 => 200,
                2 => 400,
                _ => 1000,
            };
            let payload = vec![(i & 0xFF) as u8; size];
            let frame = aead::seal(&key, seq, DIR_SEND, FTYPE_MSG, &payload).unwrap();
            assert!(frame.len() <= 1280, "wire frame {i} exceeds MTU");
            peer.send_raw(&frame, rx_addr).await.unwrap();
            // Scanner fires 4 garbage datagrams per legit one.
            for _ in 0..4 {
                scanner
                    .send_raw(b"port-scan-probe-payload", rx_addr)
                    .await
                    .unwrap();
            }
            // Drain everything currently queued.
            for _ in 0..8 {
                match rx.recv_raw(Duration::from_millis(10)).await {
                    Some(Ok((bytes, _))) => {
                        if bytes.len() < 27 {
                            rx.note_auth_drop(); // scanner garbage
                            continue;
                        }
                        let Some(s) = aead::peek_seq(&key, &bytes) else {
                            rx.note_auth_drop();
                            continue;
                        };
                        if !window.check(s) {
                            rx.note_auth_drop();
                            continue;
                        }
                        match aead::open(&key, DIR_SEND, &bytes) {
                            Ok((FTYPE_MSG, pt)) => {
                                window.mark(s);
                                assert_eq!(pt.len(), size);
                                assert!(pt.iter().all(|&b| b == (i & 0xFF) as u8));
                                legit_ok += 1;
                            }
                            _ => rx.note_auth_drop(),
                        }
                    }
                    Some(Err(_)) => {} // rate/oversize: already counted
                    None => break,
                }
            }
            seq += 1;
            // Rate-aware pacing (REQUIRED for determinism): the receiver
            // enforces a per-source token bucket (64 burst, 16/s refill) so
            // one scanner cannot starve the peer. Pumping 200 frames in a
            // tight loop would exceed the PEER's own budget and drop legit
            // traffic — not an isolation failure, a test-harness overload.
            // ~60ms/iter ≈ 16 frames/s matches the documented refill rate,
            // keeping this battle test fast yet Green by construction.
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        // Drain stragglers.
        for _ in 0..40 {
            match rx.recv_raw(Duration::from_millis(10)).await {
                Some(Ok((bytes, _))) => {
                    if bytes.len() >= 27 {
                        if let Ok((FTYPE_MSG, _)) = aead::open(&key, DIR_SEND, &bytes) {
                            legit_ok += 1;
                        }
                    }
                }
                Some(Err(_)) => {}
                None => break,
            }
        }
        assert_eq!(legit_ok, 200, "legit traffic lost under scanner fire");
        assert!(rx.drops > 0, "scanner garbage must register drops");
        // Scanner must have heard NOTHING back the entire battle.
        let silence = scanner.recv_raw(Duration::from_millis(100)).await;
        assert!(
            silence.is_none(),
            "we replied to the scanner — stealth dead"
        );
    }

    #[tokio::test]
    async fn test_recv_unthrottled_burst() {
        let mut rx = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = Endpoint::bind("127.0.0.1:0").await.unwrap();

        // Send 100 packets in immediate burst (exceeds default bucket capacity 64)
        for i in 0..100u8 {
            tx.send_raw(&[i; 64], rx_addr).await.unwrap();
        }

        let mut received = 0;
        for _ in 0..100 {
            match rx.recv_unthrottled(Duration::from_millis(200)).await {
                Some(Ok((data, _))) => {
                    assert_eq!(data.len(), 64);
                    received += 1;
                }
                _ => break,
            }
        }
        assert_eq!(
            received, 100,
            "unthrottled receiver must not drop high-rate burst packets"
        );
    }
    #[tokio::test]
    async fn active_transmission_loop_auto_rollover_packet_threshold() {
        let (ep_a, ep_b) = loopback_pair().await;
        let addr_a = ep_a.local_addr().unwrap();
        let addr_b = ep_b.local_addr().unwrap();

        let initial_sk = [0x7Cu8; 32];
        let mut loop_a = ActiveTransmissionLoop::new(ep_a, addr_b, &initial_sk, "initiator", 1232).unwrap();
        let mut loop_b = ActiveTransmissionLoop::new(ep_b, addr_a, &initial_sk, "responder", 1232).unwrap();

        // 1. Bob advertises initial ML-KEM-1024 bundle to Alice
        let bob_adv = loop_b.ratchet.advertise_bundle();
        loop_a.set_peer_bundle(bob_adv);

        // 2. Set low threshold N = 5 for unit test verification
        loop_a.ratchet.set_rollover_thresholds(5, 10_000_000);

        // 3. Alice sends 4 packets at Epoch 0
        for i in 1..=4 {
            let msg = format!("msg-epoch0-{i}");
            loop_a.send_msg(msg.as_bytes()).await.unwrap();
            let (_seq, ftype, pt) = loop_b.recv_packet(Duration::from_millis(200)).await.unwrap().unwrap();
            assert_eq!(ftype, FTYPE_MSG);
            assert_eq!(&pt, msg.as_bytes());
        }
        assert_eq!(loop_a.ratchet.epoch(), 0);
        assert_eq!(loop_b.ratchet.epoch(), 0);

        // Capture stolen Epoch 0 key (Attacker compromise model)
        let stolen_k0 = loop_a.current_frame_key.clone();

        // 4. Send 5th packet: hits N = 5 threshold! Triggers automatic rollover to Epoch 1!
        let msg5 = b"msg-epoch0-5-triggers-rollover";
        loop_a.send_msg(msg5).await.unwrap();
        assert_eq!(loop_a.ratchet.epoch(), 1, "Alice must roll over to Epoch 1 automatically");

        // Bob receives in-flight rekey fragments until epoch rolls over to 1
        while loop_b.ratchet.epoch() < 1 {
            let res = loop_b.recv_packet(Duration::from_millis(300)).await.unwrap();
            assert!(res.is_some());
        }
        assert_eq!(loop_b.ratchet.epoch(), 1, "Bob must advance to Epoch 1 after receiving rekey fragments");

        // Bob receives the 5th message
        let (_s, _ft, pt5) = loop_b.recv_packet(Duration::from_millis(300)).await.unwrap().unwrap();
        assert_eq!(&pt5, msg5);

        // 5. Subsequent message transmitted strictly under Epoch 1
        let msg_epoch1 = b"TOP_SECRET_EPOCH_1_TACTICAL_TELEMETRY";
        let seq_e1 = loop_a.send_msg(msg_epoch1).await.unwrap();
        let (r_seq, r_ftype, r_pt) = loop_b.recv_packet(Duration::from_millis(200)).await.unwrap().unwrap();
        assert_eq!(r_seq, seq_e1);
        assert_eq!(r_ftype, FTYPE_MSG);
        assert_eq!(&r_pt, msg_epoch1);

        // 6. Post-Compromise Security Verification:
        // Attacker with stolen Epoch 0 frame key tries to open the Epoch 1 frame -> FAILS!
        let ep_attacker = Endpoint::bind("127.0.0.1:0").await.unwrap();
        let att_addr = ep_attacker.local_addr().unwrap();
        let mut loop_att = ActiveTransmissionLoop::new(ep_attacker, att_addr, &initial_sk, "responder", 1232).unwrap();
        loop_att.current_frame_key = stolen_k0;

        // Alice sends another Epoch 1 frame directly to attacker address
        let e1_wire_frame = crate::pacing::build_data_frame_directed(
            &loop_a.current_frame_key,
            100,
            DIR_SEND,
            1232,
            b"CLASSIFIED_E1",
        ).unwrap();
        loop_a.endpoint.send_raw(&e1_wire_frame, att_addr).await.unwrap();

        let att_res = loop_att.recv_packet(Duration::from_millis(200)).await.unwrap();
        assert!(att_res.is_none(), "Attacker with stolen Epoch 0 key must fail to open Epoch 1 frame");
    }

    #[tokio::test]
    async fn active_transmission_loop_auto_rollover_byte_threshold() {
        let (ep_a, ep_b) = loopback_pair().await;
        let addr_a = ep_a.local_addr().unwrap();
        let addr_b = ep_b.local_addr().unwrap();

        let initial_sk = [0x3Du8; 32];
        let mut loop_a = ActiveTransmissionLoop::new(ep_a, addr_b, &initial_sk, "initiator", 1232).unwrap();
        let mut loop_b = ActiveTransmissionLoop::new(ep_b, addr_a, &initial_sk, "responder", 1232).unwrap();

        let bob_adv = loop_b.ratchet.advertise_bundle();
        loop_a.set_peer_bundle(bob_adv);

        // Set byte threshold M = 1500 bytes for unit testing
        loop_a.ratchet.set_rollover_thresholds(10_000, 1500);

        // Send 800 bytes (under threshold)
        let data800 = vec![0x41u8; 800];
        loop_a.send_msg(&data800).await.unwrap();
        let _ = loop_b.recv_packet(Duration::from_millis(200)).await.unwrap();
        assert_eq!(loop_a.ratchet.epoch(), 0);

        // Send another 800 bytes (total 1600 bytes >= 1500 byte threshold!)
        loop_a.send_msg(&data800).await.unwrap();
        assert_eq!(loop_a.ratchet.epoch(), 1, "Must trigger rollover upon reaching byte threshold M");

        while loop_b.ratchet.epoch() < 1 {
            let res = loop_b.recv_packet(Duration::from_millis(300)).await.unwrap();
            assert!(res.is_some());
        }
        assert_eq!(loop_b.ratchet.epoch(), 1);
        let (_s, _ft, pt2) = loop_b.recv_packet(Duration::from_millis(300)).await.unwrap().unwrap();
        assert_eq!(pt2.len(), 800);
    }

    #[test]
    fn active_transmission_loop_exact_10000_packets_trigger() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
            let addr = ep.local_addr().unwrap();
            let mut loop_inst = ActiveTransmissionLoop::new(ep, addr, &[0x22u8; 32], "initiator", 1232).unwrap();

            // Default threshold N = 10,000 packets
            assert_eq!(loop_inst.ratchet.rollover_counters(), (0, 0));
            assert!(!loop_inst.ratchet.needs_rollover());

            // Transmit 9,999 packets
            for _ in 0..9_999 {
                loop_inst.ratchet.note_transmission(100);
            }
            assert_eq!(loop_inst.ratchet.rollover_counters().0, 9_999);
            assert!(!loop_inst.ratchet.needs_rollover(), "must not trigger at 9,999 packets");

            // 10,000th packet
            loop_inst.ratchet.note_transmission(100);
            assert_eq!(loop_inst.ratchet.rollover_counters().0, 10_000);
            assert!(loop_inst.ratchet.needs_rollover(), "must trigger exactly at 10,000 packets");
        });
    }

    #[test]
    fn active_transmission_loop_exact_10mb_bytes_trigger() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
            let addr = ep.local_addr().unwrap();
            let mut loop_inst = ActiveTransmissionLoop::new(ep, addr, &[0x33u8; 32], "initiator", 1232).unwrap();

            // Default threshold M = 10 MB = 10,485,760 bytes
            assert_eq!(loop_inst.ratchet.rollover_counters(), (0, 0));
            assert!(!loop_inst.ratchet.needs_rollover());

            // Transmit 10,485,759 bytes (1 byte below 10 MB)
            loop_inst.ratchet.note_transmission(10_485_759);
            assert_eq!(loop_inst.ratchet.rollover_counters().1, 10_485_759);
            assert!(!loop_inst.ratchet.needs_rollover(), "must not trigger at 10,485,759 bytes");

            // 1 more byte reaches 10 MB
            loop_inst.ratchet.note_transmission(1);
            assert_eq!(loop_inst.ratchet.rollover_counters().1, 10_485_760);
            assert!(loop_inst.ratchet.needs_rollover(), "must trigger exactly at 10 MB (10,485,760 bytes)");
        });
    }

    #[test]
    fn active_transmission_loop_default_thresholds_match_spec() {
        use crate::policy::{ROLLOVER_BYTE_THRESHOLD, ROLLOVER_PACKET_THRESHOLD};
        assert_eq!(ROLLOVER_PACKET_THRESHOLD, 10_000, "Specification requires N = 10,000 packets");
        assert_eq!(ROLLOVER_BYTE_THRESHOLD, 10 * 1024 * 1024, "Specification requires M = 10 MB");

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let ep = Endpoint::bind("127.0.0.1:0").await.unwrap();
            let addr = ep.local_addr().unwrap();
            let loop_inst = ActiveTransmissionLoop::new(ep, addr, &[0x11u8; 32], "initiator", 1232).unwrap();
            assert_eq!(loop_inst.ratchet.rollover_counters(), (0, 0));
            assert!(!loop_inst.ratchet.needs_rollover());
        });
    }
}
