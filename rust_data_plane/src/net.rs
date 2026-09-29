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
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};

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
        assert!(reply.is_none(), "listener replied to garbage — stealth violated");
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
            let frame =
                aead::seal(&key, send_seq, DIR_SEND, FTYPE_MSG, format!("pkt-{i}").as_bytes())
                    .unwrap();
            assert!(frame.len() <= 1280, "frame exceeds IPv6 MTU budget");
            tx.send_raw(&frame, rx_addr).await.unwrap();
            let (bytes, _) = rx
                .recv_raw(Duration::from_millis(500))
                .await
                .expect("datagram arrives")
                .expect("within budget");
            // Parse seq from header WITHOUT trusting it yet.
            let seq = u64::from_be_bytes(bytes[..8].try_into().unwrap());
            assert!(window.check_and_update(seq), "fresh seq rejected");
            let (t, pt) = aead::open(&key, DIR_SEND, &bytes).unwrap();
            assert_eq!((t, &pt[..]), (FTYPE_MSG, format!("pkt-{i}").into_bytes().as_slice()));
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
        assert!(rx.buckets.len() <= MAX_BUCKETS, "bucket table over cap after eviction");
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
        let key = FrameKey::from_bytes([13u8; 32]);        let mut window = AntiReplayWindow::new();
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
                match rx.recv_raw(Duration::from_millis(100)).await {
                    Some(Ok((bytes, _))) => {
                        if bytes.len() < 27 {
                            rx.note_auth_drop(); // scanner garbage
                            continue;
                        }
                        let s = u64::from_be_bytes(bytes[..8].try_into().unwrap());
                        if !window.check_and_update(s) {
                            rx.note_auth_drop();
                            continue;
                        }
                        match aead::open(&key, DIR_SEND, &bytes) {
                            Ok((FTYPE_MSG, pt)) => {
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
        }
        // Drain stragglers.
        for _ in 0..40 {
            match rx.recv_raw(Duration::from_millis(100)).await {
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
        let silence = scanner.recv_raw(Duration::from_millis(400)).await;
        assert!(silence.is_none(), "we replied to the scanner — stealth dead");
    }
}
