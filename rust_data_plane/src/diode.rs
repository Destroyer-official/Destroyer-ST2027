//! diode.rs — Simplex Optical Data Diode Transmission Engine with Cauchy-Reed-Solomon FEC.
//!
//! Conforming to:
//! - Physical glass optical data diode architecture (unidirectional transmit fiber only, zero return wire).
//! - Zero reverse channel / zero ACKs security invariant.
//! - Tolerates up to 25% (and up to 33%+) burst packet loss with 100% bitwise reconstruction.
//! - Post-quantum digital signatures: each 1232-byte chunk packet is signed with ML-DSA-87 (FIPS 204).

use std::collections::HashMap;
use std::fmt;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::auth::{Mldsa87SigningKey, Mldsa87VerifyingKey};
use crate::fec::{CauchyReedSolomon, FecError};
use crate::policy::{CoreError, MLDSA87_PK, MLDSA87_SIG};

/// Fixed chunk payload size (standard tactical cell quantum).
pub const CHUNK_PAYLOAD_SIZE: usize = 1232;

/// Magic wire identifier for Simplex Optical Data Diode frames.
pub const DIODE_MAGIC: &[u8; 4] = b"ODD1";

/// Domain separation tag for ML-DSA-87 optical diode chunk signatures.
pub const OPTICAL_DIODE_DOMAIN: &[u8] = b"ST2027-OPTICAL-DIODE-SIMPLEX-v1";

/// Wire header length before chunk data:
/// 4 (magic) + 16 (transfer_id) + 8 (total_len) + 2 (k) + 2 (n) + 2 (chunk_idx)
/// + 2 (chunk_len) + 32 (chunk_sha256) + 2592 (sender_vk) + 4627 (mldsa87_sig)
///   = 7287 bytes.
pub const DIODE_HEADER_LEN: usize = 4 + 16 + 8 + 2 + 2 + 2 + 2 + 32 + MLDSA87_PK + MLDSA87_SIG;

/// Total wire packet length for standard 1232-byte tactical chunk: 7287 + 1232 = 8519 bytes.
pub const DIODE_PACKET_LEN: usize = DIODE_HEADER_LEN + CHUNK_PAYLOAD_SIZE;

#[derive(Debug)]
pub enum DiodeError {
    Fec(FecError),
    Auth(CoreError),
    Io(std::io::Error),
    MalformedPacket(&'static str),
    SignatureVerificationFailed,
    UnauthorizedSender,
    PayloadTooLarge,
    Timeout,
}

impl fmt::Display for DiodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiodeError::Fec(e) => write!(f, "Diode FEC error: {e}"),
            DiodeError::Auth(e) => write!(f, "Diode authentication error: {e}"),
            DiodeError::Io(e) => write!(f, "Diode I/O error: {e}"),
            DiodeError::MalformedPacket(msg) => write!(f, "Diode packet malformed: {msg}"),
            DiodeError::SignatureVerificationFailed => {
                write!(f, "Diode ML-DSA-87 signature verification failed (corrupt or forged)")
            }
            DiodeError::UnauthorizedSender => {
                write!(f, "Diode sender public key does not match enrolled trust pin")
            }
            DiodeError::PayloadTooLarge => write!(f, "Diode payload exceeds maximum chunking capacity"),
            DiodeError::Timeout => write!(f, "Diode receiver timed out awaiting sufficient chunks"),
        }
    }
}

impl std::error::Error for DiodeError {}

impl From<FecError> for DiodeError {
    fn from(e: FecError) -> Self {
        DiodeError::Fec(e)
    }
}

impl From<CoreError> for DiodeError {
    fn from(e: CoreError) -> Self {
        DiodeError::Auth(e)
    }
}

impl From<std::io::Error> for DiodeError {
    fn from(e: std::io::Error) -> Self {
        DiodeError::Io(e)
    }
}

/// A serialized and signed diode chunk packet crossing the unidirectional boundary.
#[derive(Clone, Debug)]
pub struct DiodePacket {
    pub magic: [u8; 4],
    pub transfer_id: [u8; 16],
    pub total_len: u64,
    pub k: u16,
    pub n: u16,
    pub chunk_index: u16,
    pub chunk_len: u16,
    pub chunk_hash: [u8; 32],
    pub sender_vk: [u8; MLDSA87_PK],
    pub signature: [u8; MLDSA87_SIG],
    pub chunk_data: Vec<u8>,
}

impl DiodePacket {
    /// Compute the To-Be-Signed (TBS) bytes over metadata and chunk payload.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_tbs(
        magic: &[u8; 4],
        transfer_id: &[u8; 16],
        total_len: u64,
        k: u16,
        n: u16,
        chunk_index: u16,
        chunk_len: u16,
        chunk_hash: &[u8; 32],
        chunk_data: &[u8],
    ) -> Vec<u8> {
        let mut tbs = Vec::with_capacity(4 + 16 + 8 + 2 + 2 + 2 + 2 + 32 + chunk_data.len());
        tbs.extend_from_slice(magic);
        tbs.extend_from_slice(transfer_id);
        tbs.extend_from_slice(&total_len.to_be_bytes());
        tbs.extend_from_slice(&k.to_be_bytes());
        tbs.extend_from_slice(&n.to_be_bytes());
        tbs.extend_from_slice(&chunk_index.to_be_bytes());
        tbs.extend_from_slice(&chunk_len.to_be_bytes());
        tbs.extend_from_slice(chunk_hash);
        tbs.extend_from_slice(chunk_data);
        tbs
    }

    /// Construct and sign a fresh diode packet with ML-DSA-87.
    pub fn create_and_sign(
        signing_key: &Mldsa87SigningKey,
        transfer_id: [u8; 16],
        total_len: u64,
        k: u16,
        n: u16,
        chunk_index: u16,
        chunk_data: &[u8],
    ) -> Result<Self, DiodeError> {
        let mut hasher = Sha256::new();
        hasher.update(chunk_data);
        let chunk_hash: [u8; 32] = hasher.finalize().into();

        let chunk_len = chunk_data.len() as u16;
        let tbs = Self::compute_tbs(
            DIODE_MAGIC,
            &transfer_id,
            total_len,
            k,
            n,
            chunk_index,
            chunk_len,
            &chunk_hash,
            chunk_data,
        );

        let sig_bytes = signing_key.sign(OPTICAL_DIODE_DOMAIN, &tbs);
        let mut signature = [0u8; MLDSA87_SIG];
        if sig_bytes.len() != MLDSA87_SIG {
            return Err(DiodeError::MalformedPacket("ML-DSA-87 signature length mismatch"));
        }
        signature.copy_from_slice(&sig_bytes);

        let vk_bytes = signing_key.verifying_bytes();
        let mut sender_vk = [0u8; MLDSA87_PK];
        if vk_bytes.len() != MLDSA87_PK {
            return Err(DiodeError::MalformedPacket("ML-DSA-87 verifying key length mismatch"));
        }
        sender_vk.copy_from_slice(&vk_bytes);

        Ok(Self {
            magic: *DIODE_MAGIC,
            transfer_id,
            total_len,
            k,
            n,
            chunk_index,
            chunk_len,
            chunk_hash,
            sender_vk,
            signature,
            chunk_data: chunk_data.to_vec(),
        })
    }

    /// Serialize this packet to bytes for transmission over simplex link.
    pub fn serialize(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(DIODE_HEADER_LEN + self.chunk_data.len());
        wire.extend_from_slice(&self.magic);
        wire.extend_from_slice(&self.transfer_id);
        wire.extend_from_slice(&self.total_len.to_be_bytes());
        wire.extend_from_slice(&self.k.to_be_bytes());
        wire.extend_from_slice(&self.n.to_be_bytes());
        wire.extend_from_slice(&self.chunk_index.to_be_bytes());
        wire.extend_from_slice(&self.chunk_len.to_be_bytes());
        wire.extend_from_slice(&self.chunk_hash);
        wire.extend_from_slice(&self.sender_vk);
        wire.extend_from_slice(&self.signature);
        wire.extend_from_slice(&self.chunk_data);
        wire
    }

    /// Deserialize and cryptographically verify inbound packet bytes.
    pub fn deserialize(wire: &[u8]) -> Result<Self, DiodeError> {
        if wire.len() < DIODE_HEADER_LEN {
            return Err(DiodeError::MalformedPacket("packet shorter than minimum header"));
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&wire[0..4]);
        if &magic != DIODE_MAGIC {
            return Err(DiodeError::MalformedPacket("invalid diode magic"));
        }

        let mut transfer_id = [0u8; 16];
        transfer_id.copy_from_slice(&wire[4..20]);

        let total_len = u64::from_be_bytes(wire[20..28].try_into().unwrap());
        let k = u16::from_be_bytes(wire[28..30].try_into().unwrap());
        let n = u16::from_be_bytes(wire[30..32].try_into().unwrap());
        let chunk_index = u16::from_be_bytes(wire[32..34].try_into().unwrap());
        let chunk_len = u16::from_be_bytes(wire[34..36].try_into().unwrap());

        if k == 0 || n < k || n > 255 || chunk_index >= n {
            return Err(DiodeError::MalformedPacket("invalid K/N/chunk_index parameters"));
        }

        let mut chunk_hash = [0u8; 32];
        chunk_hash.copy_from_slice(&wire[36..68]);

        let mut sender_vk = [0u8; MLDSA87_PK];
        sender_vk.copy_from_slice(&wire[68..68 + MLDSA87_PK]);

        let mut signature = [0u8; MLDSA87_SIG];
        let sig_offset = 68 + MLDSA87_PK;
        signature.copy_from_slice(&wire[sig_offset..sig_offset + MLDSA87_SIG]);

        let payload_offset = sig_offset + MLDSA87_SIG;
        let chunk_data = wire[payload_offset..].to_vec();
        if chunk_data.len() != (chunk_len as usize) {
            return Err(DiodeError::MalformedPacket("chunk payload length mismatch"));
        }

        // 1. Verify SHA-256 chunk hash
        let mut hasher = Sha256::new();
        hasher.update(&chunk_data);
        let actual_hash: [u8; 32] = hasher.finalize().into();
        if actual_hash != chunk_hash {
            return Err(DiodeError::MalformedPacket("chunk SHA-256 integrity mismatch"));
        }

        // 2. Cryptographically verify ML-DSA-87 signature
        let tbs = Self::compute_tbs(
            &magic,
            &transfer_id,
            total_len,
            k,
            n,
            chunk_index,
            chunk_len,
            &chunk_hash,
            &chunk_data,
        );

        let vk = Mldsa87VerifyingKey::from_bytes(&sender_vk)?;
        vk.verify(OPTICAL_DIODE_DOMAIN, &tbs, &signature)
            .map_err(|_| DiodeError::SignatureVerificationFailed)?;

        Ok(Self {
            magic,
            transfer_id,
            total_len,
            k,
            n,
            chunk_index,
            chunk_len,
            chunk_hash,
            sender_vk,
            signature,
            chunk_data,
        })
    }
}

/// Pure Simplex Diode Sender:
/// - Splits cleartext into K data chunks + M parity chunks (N = K + M) of 1232 bytes.
/// - Signs each chunk with ML-DSA-87.
/// - Unidirectionally transmits over UDP broadcast / unicast with ZERO listener sockets.
/// - Invariant: Zero reverse channel, zero ACKs.
pub struct DiodeSender {
    signing_key: Mldsa87SigningKey,
    verifying_key_bytes: Vec<u8>,
}

impl DiodeSender {
    pub fn new(signing_key: Mldsa87SigningKey) -> Self {
        let verifying_key_bytes = signing_key.verifying_bytes();
        Self {
            signing_key,
            verifying_key_bytes,
        }
    }

    /// Generate fresh ML-DSA-87 keypair and instantiate sender.
    pub fn generate() -> Result<Self, DiodeError> {
        let (sk, _) = Mldsa87SigningKey::generate()?;
        Ok(Self::new(sk))
    }

    pub fn verifying_key_bytes(&self) -> &[u8] {
        &self.verifying_key_bytes
    }

    /// Splits payload into K data + M parity chunks of 1232 bytes and signs each with ML-DSA-87.
    /// Default parity ratio provides >= 25% burst loss tolerance.
    pub fn prepare_packets(
        &self,
        payload: &[u8],
        k_override: Option<usize>,
        m_override: Option<usize>,
    ) -> Result<([u8; 16], Vec<Vec<u8>>), DiodeError> {
        let total_len = payload.len();
        if total_len == 0 {
            return Err(DiodeError::MalformedPacket("refusing empty payload"));
        }

        // Determine K (data chunks)
        let k = match k_override {
            Some(k_val) => {
                if k_val == 0 || k_val * CHUNK_PAYLOAD_SIZE < total_len {
                    return Err(DiodeError::PayloadTooLarge);
                }
                k_val
            }
            None => total_len.div_ceil(CHUNK_PAYLOAD_SIZE),
        };

        if k > 200 {
            return Err(DiodeError::PayloadTooLarge);
        }

        // Determine M (parity chunks).
        // By default, M = ceil(K * 0.35) with minimum 2, ensuring >= 25% loss tolerance.
        let m = match m_override {
            Some(m_val) => {
                if m_val == 0 {
                    return Err(DiodeError::MalformedPacket("parity chunks M must be >= 1"));
                }
                m_val
            }
            None => {
                let calculated = ((k as f64) * 0.35).ceil() as usize;
                calculated.max(2)
            }
        };

        if k + m > 255 {
            return Err(DiodeError::Fec(FecError::TooManyChunks));
        }

        let n = k + m;
        let crs = CauchyReedSolomon::new(k, m)?;
        let encoded_chunks = crs.encode_payload(payload, CHUNK_PAYLOAD_SIZE)?;

        // Random 16-byte transfer ID
        let mut transfer_id = [0u8; 16];
        if getrandom::fill(&mut transfer_id).is_err() {
            return Err(DiodeError::MalformedPacket("getrandom failed"));
        }

        let mut packets = Vec::with_capacity(n);
        for (idx, chunk) in encoded_chunks.iter().enumerate() {
            let pkt = DiodePacket::create_and_sign(
                &self.signing_key,
                transfer_id,
                total_len as u64,
                k as u16,
                n as u16,
                idx as u16,
                chunk,
            )?;
            packets.push(pkt.serialize());
        }

        Ok((transfer_id, packets))
    }

    /// Unidirectional simplex blast over UDP broadcast / unicast.
    /// Strictly opens ONLY an ephemeral transmit socket (never binds a listener, never calls recv).
    pub fn send_simplex_udp(
        &self,
        payload: &[u8],
        target_addr: &str,
        k_override: Option<usize>,
        m_override: Option<usize>,
        burst_delay: Duration,
    ) -> Result<[u8; 16], DiodeError> {
        let (transfer_id, packets) = self.prepare_packets(payload, k_override, m_override)?;

        let any = if target_addr.contains('[') || target_addr.starts_with("::") {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let sock = UdpSocket::bind(any)?;
        let _ = sock.set_broadcast(true);

        for packet in &packets {
            sock.send_to(packet, target_addr)?;
            if !burst_delay.is_zero() {
                std::thread::sleep(burst_delay);
            }
        }

        Ok(transfer_id)
    }
}

/// Internal state tracking an in-flight diode transmission.
struct DiodeTransferState {
    total_len: usize,
    k: usize,
    n: usize,
    pub _chunk_len: usize,
    created_at: Instant,
    received_chunks: HashMap<usize, Vec<u8>>,
}

impl Drop for DiodeTransferState {
    fn drop(&mut self) {
        for (_, mut chunk) in self.received_chunks.drain() {
            chunk.zeroize();
        }
    }
}

/// Pure Simplex Diode Receiver:
/// - Strictly opens ONLY a listener socket (never transmits, cannot ACK/NACK).
/// - Deduplicates and cryptographically verifies ML-DSA-87 signatures on every packet.
/// - Reassembles full original payload as soon as ANY K valid chunks arrive.
/// - Hardened with DoS eviction and in-flight TTL expiration.
pub struct DiodeReceiver {
    expected_sender_vk: Option<Vec<u8>>,
    transfer_ttl: Duration,
    max_concurrent_transfers: usize,
    transfers: HashMap<[u8; 16], DiodeTransferState>,
}

impl DiodeReceiver {
    pub fn new(expected_sender_vk: Option<Vec<u8>>) -> Self {
        Self::with_config(expected_sender_vk, Duration::from_secs(30), 128)
    }

    pub fn with_config(
        expected_sender_vk: Option<Vec<u8>>,
        transfer_ttl: Duration,
        max_concurrent_transfers: usize,
    ) -> Self {
        Self {
            expected_sender_vk,
            transfer_ttl,
            max_concurrent_transfers,
            transfers: HashMap::new(),
        }
    }

    /// Prune stale in-flight transfers older than transfer_ttl or when exceeding max capacity.
    pub fn prune_stale_transfers(&mut self) {
        let ttl = self.transfer_ttl;
        let now = Instant::now();
        self.transfers
            .retain(|_, state| now.duration_since(state.created_at) < ttl);

        if self.transfers.len() > self.max_concurrent_transfers {
            // Evict oldest transfer
            if let Some((&oldest_id, _)) = self
                .transfers
                .iter()
                .min_by_key(|(_, s)| s.created_at)
            {
                self.transfers.remove(&oldest_id);
            }
        }
    }

    /// Process a single raw packet from the simplex optical link.
    /// Returns `Ok(Some(payload))` if threshold K reached and payload reconstructed,
    /// `Ok(None)` if more chunks needed, or `Err` if malformed/unauthorized.
    pub fn process_packet(&mut self, wire: &[u8]) -> Result<Option<Vec<u8>>, DiodeError> {
        self.prune_stale_transfers();
        let pkt = DiodePacket::deserialize(wire)?;

        // Enforce pinned sender key if configured
        if let Some(ref expected) = self.expected_sender_vk {
            if &pkt.sender_vk[..] != expected.as_slice() {
                return Err(DiodeError::UnauthorizedSender);
            }
        }

        let state = self.transfers.entry(pkt.transfer_id).or_insert_with(|| DiodeTransferState {
            total_len: pkt.total_len as usize,
            k: pkt.k as usize,
            n: pkt.n as usize,
            _chunk_len: pkt.chunk_len as usize,
            created_at: Instant::now(),
            received_chunks: HashMap::new(),
        });

        // Store chunk (deduplicated by chunk_index)
        state.received_chunks.insert(pkt.chunk_index as usize, pkt.chunk_data);

        // Check if we have received at least K valid distinct chunks
        if state.received_chunks.len() >= state.k {
            let k = state.k;
            let m = state.n - state.k;
            let total_len = state.total_len;

            let crs = CauchyReedSolomon::new(k, m)?;
            let chunk_refs: Vec<(usize, &[u8])> = state
                .received_chunks
                .iter()
                .map(|(&idx, data)| (idx, data.as_slice()))
                .collect();

            let payload = crs.decode_payload(&chunk_refs, total_len)?;

            // Clean up transfer state upon successful reassembly (triggers zeroizing Drop)
            self.transfers.remove(&pkt.transfer_id);
            return Ok(Some(payload));
        }

        Ok(None)
    }

    /// Listen on UDP socket until complete payload reassembly or timeout.
    /// Strictly NEVER calls send/sendto. Zero reverse channel.
    pub fn listen_simplex_udp(
        &mut self,
        bind_addr: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, DiodeError> {
        let sock = UdpSocket::bind(bind_addr)?;
        sock.set_read_timeout(Some(Duration::from_millis(100)))?;

        let mut buf = [0u8; 65536];
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            match sock.recv_from(&mut buf) {
                Ok((amt, _)) => {
                    match self.process_packet(&buf[..amt]) {
                        Ok(Some(payload)) => return Ok(payload),
                        Ok(None) => {}
                        Err(_) => {
                            // In simplex diodes, bad packets are silently dropped (no NACKs)
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(e) => return Err(DiodeError::Io(e)),
            }
        }

        Err(DiodeError::Timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diode_packet_sign_and_verify() {
        let (sk, _) = Mldsa87SigningKey::generate().unwrap();
        let payload = b"OPTICAL_DIODE_SECRET_TELEMETRY";
        let transfer_id = [7u8; 16];

        let pkt = DiodePacket::create_and_sign(
            &sk,
            transfer_id,
            payload.len() as u64,
            4,
            6,
            0,
            payload,
        )
        .expect("create_and_sign failed");

        let wire = pkt.serialize();
        assert_eq!(wire.len(), DIODE_HEADER_LEN + payload.len());

        let restored = DiodePacket::deserialize(&wire).expect("deserialize failed");
        assert_eq!(restored.transfer_id, transfer_id);
        assert_eq!(restored.chunk_data, payload);
    }

    #[test]
    fn test_diode_tampered_packet_fails_verification() {
        let (sk, _) = Mldsa87SigningKey::generate().unwrap();
        let payload = b"GENUINE_DATA_STREAM";
        let transfer_id = [9u8; 16];

        let pkt = DiodePacket::create_and_sign(
            &sk,
            transfer_id,
            payload.len() as u64,
            2,
            3,
            0,
            payload,
        )
        .unwrap();

        let mut wire = pkt.serialize();
        // Tamper with the last byte of payload
        let last = wire.len() - 1;
        wire[last] ^= 0x55;

        let result = DiodePacket::deserialize(&wire);
        assert!(result.is_err(), "Tampered packet must fail verification fail-closed");
    }

    #[test]
    fn test_diode_sender_receiver_25_percent_burst_loss() {
        let sender = DiodeSender::generate().unwrap();
        let mut receiver = DiodeReceiver::new(Some(sender.verifying_key_bytes().to_vec()));

        // Create a 5000-byte test payload
        let test_payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();

        // Prepare packets: K = 5 (5 * 1232 = 6160 > 5000), default M will be >= 2 -> total N >= 7
        // Let's specify K=8, M=4 -> N=12
        let (_tx_id, packets) = sender
            .prepare_packets(&test_payload, Some(8), Some(4))
            .expect("prepare_packets failed");
        assert_eq!(packets.len(), 12);

        // 25% burst packet loss: drop 3 packets out of 12 (drop indices 0, 1, 2)
        // 9 packets remain (chunks 3..11), which is >= K (8)
        let dropped_indices = [0, 1, 2];
        let mut recovered_payload = None;

        for (idx, pkt_bytes) in packets.iter().enumerate() {
            if dropped_indices.contains(&idx) {
                continue; // Packet dropped by optical lossy channel
            }
            if let Some(payload) = receiver
                .process_packet(pkt_bytes)
                .expect("packet processing should succeed")
            {
                recovered_payload = Some(payload);
                break;
            }
        }

        assert_eq!(
            recovered_payload,
            Some(test_payload),
            "Payload must be 100% bitwise reconstructed after 25% burst packet loss"
        );
    }

    #[test]
    fn test_diode_sender_receiver_33_percent_loss() {
        let sender = DiodeSender::generate().unwrap();
        let mut receiver = DiodeReceiver::new(None);

        let test_payload = b"TOP-SECRET-SIMPLEX-OPTICAL-GLASS-TRANSMISSION-DATA";
        // K=4, M=2 (total 6). Drop 2 packets (33.3% loss!)
        let (_, packets) = sender
            .prepare_packets(test_payload, Some(4), Some(2))
            .expect("prepare_packets failed");
        assert_eq!(packets.len(), 6);

        // Drop packets 0 and 1 (first two data packets)
        let mut recovered = None;
        for packet in packets.iter().take(6).skip(2) {
            if let Some(p) = receiver.process_packet(packet).unwrap() {
                recovered = Some(p);
                break;
            }
        }

        assert_eq!(recovered, Some(test_payload.to_vec()));
    }

    #[test]
    fn test_diode_receiver_dos_ttl_eviction() {
        let sender = DiodeSender::generate().unwrap();
        // Construct receiver with 10ms TTL and max 2 transfers
        let mut receiver = DiodeReceiver::with_config(None, Duration::from_millis(10), 2);

        let (_, packets) = sender
            .prepare_packets(b"DATA-FOR-EVICTION", Some(4), Some(2))
            .unwrap();

        // Process only first packet (chunk 0)
        let res = receiver.process_packet(&packets[0]).unwrap();
        assert!(res.is_none());
        assert_eq!(receiver.transfers.len(), 1);

        // Sleep to let TTL expire
        std::thread::sleep(Duration::from_millis(25));
        receiver.prune_stale_transfers();
        assert_eq!(receiver.transfers.len(), 0, "Stale transfer must be evicted on TTL expiration");
    }
}
