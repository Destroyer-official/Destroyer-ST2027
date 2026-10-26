//! Stateless Anti-Amplification & Anti-DoS Cookie Gate (RFC 9000 / WireGuard style).
//!
//! Protects Noise_XXhfs responders from CPU exhaustion and reflection attacks:
//! 1. M1 is 1,665 bytes while M2 is 8,916 bytes (a 5.35x amplification factor).
//! 2. Generating M2 requires P-384 ECDH keygen, ML-KEM encapsulation, and ML-DSA-87 signature.
//! 3. Validates sender address return-routability before any asymmetric crypto is computed.
//! 4. Optional micro-Proof-of-Work (PoW) challenge dynamically scales under high ingress load.
//!
//! Bit-for-bit compatible with `noise_pq.StatelessCookieGate`.

use aes_gcm::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const COOKIE_MAGIC: &[u8; 6] = b"NPQC1\0";
pub const CHALLENGE_PREFIX: &[u8; 14] = b"NPQ_CHALLENGE\0";
pub const COOKIE_M1_PREFIX: &[u8; 6] = b"NPQK1\0";
pub const EXPECTED_M1_LEN: usize = 1665;
pub const DEFAULT_ROTATION_SECS: u64 = 120;
pub const COOKIE_LEN: usize = 38; // 6 (magic) + 8 (epoch) + 24 (hmac)
pub const RESPONSE_LEN: usize = COOKIE_LEN + 8; // 38 + 8 (nonce)

/// Unpack wire payload into (optional cookie solution, m1 payload).
pub fn unpack_cookie_m1(wire: &[u8]) -> (Option<&[u8]>, &[u8]) {
    if wire.starts_with(COOKIE_M1_PREFIX) && wire.len() > COOKIE_M1_PREFIX.len() + 2 {
        let off = COOKIE_M1_PREFIX.len();
        let clen = u16::from_be_bytes([wire[off], wire[off + 1]]) as usize;
        let start = off + 2;
        if wire.len() >= start + clen {
            let solution = &wire[start..start + clen];
            let m1 = &wire[start + clen..];
            return (Some(solution), m1);
        }
    }
    (None, wire)
}

type HmacSha384 = Hmac<Sha384>;

fn leading_zeros_256(hash: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for &b in hash {
        let lz = b.leading_zeros();
        count += lz;
        if lz < 8 {
            break;
        }
    }
    count
}

/// Thread-safe stateless cookie gate with epoch secret rotation and single-use PoW cache.
pub struct StatelessCookieGate {
    rotation_interval: u64,
    curr_secret: [u8; 32],
    prev_secret: [u8; 32],
    last_rotation: u64,
    seen_solutions: Mutex<HashMap<Vec<u8>, u64>>,
    max_cached_solutions: usize,
}

impl Drop for StatelessCookieGate {
    fn drop(&mut self) {
        self.curr_secret.zeroize();
        self.prev_secret.zeroize();
    }
}

impl StatelessCookieGate {
    /// Initialize with rotation interval and maximum cache capacity.
    pub fn new(rotation_interval: u64, max_cached_solutions: usize) -> Self {
        let interval = rotation_interval.max(10);
        let mut curr = [0u8; 32];
        let _ = getrandom::fill(&mut curr);
        let prev = curr;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            rotation_interval: interval,
            curr_secret: curr,
            prev_secret: prev,
            last_rotation: now,
            seen_solutions: Mutex::new(HashMap::with_capacity(1024)),
            max_cached_solutions: max_cached_solutions.max(256),
        }
    }

    /// Initialize with an explicit 32-byte secret for deterministic / persistent verification.
    pub fn with_secret(
        mut secret: [u8; 32],
        rotation_interval: u64,
        max_cached_solutions: usize,
    ) -> Self {
        let interval = rotation_interval.max(10);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let s = Self {
            rotation_interval: interval,
            curr_secret: secret,
            prev_secret: secret,
            last_rotation: now,
            seen_solutions: Mutex::new(HashMap::with_capacity(1024)),
            max_cached_solutions: max_cached_solutions.max(256),
        };
        secret.zeroize();
        s
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn maybe_rotate(&mut self) {
        let now = Self::now_secs();
        if now.saturating_sub(self.last_rotation) >= self.rotation_interval {
            self.prev_secret = self.curr_secret;
            let mut next = [0u8; 32];
            let _ = getrandom::fill(&mut next);
            self.curr_secret = next;
            self.last_rotation = now;

            // Prune expired seen solutions
            if let Ok(mut seen) = self.seen_solutions.lock() {
                let cutoff = now.saturating_sub(2 * self.rotation_interval);
                seen.retain(|_, &mut ts| ts >= cutoff);
            }
        }
    }

    fn epoch(&self) -> u64 {
        Self::now_secs() / self.rotation_interval
    }

    fn compute_mac(
        secret: &[u8; 32],
        client_ip: &str,
        client_port: u16,
        m1_prefix: &[u8],
        epoch: u64,
    ) -> [u8; 24] {
        let mut mac = match HmacSha384::new_from_slice(secret) {
            Ok(m) => m,
            Err(_) => return [0u8; 24],
        };
        mac.update(client_ip.as_bytes());
        mac.update(&client_port.to_be_bytes());
        let pfx_len = m1_prefix.len().min(64);
        mac.update(&m1_prefix[..pfx_len]);
        mac.update(&epoch.to_be_bytes());

        let full = mac.finalize().into_bytes();
        let mut out = [0u8; 24];
        out.copy_from_slice(&full[..24]);
        out
    }

    /// Create an address-bound 38-byte stateless cookie.
    pub fn create_cookie(
        &mut self,
        client_ip: &str,
        client_port: u16,
        m1_prefix: &[u8],
    ) -> Vec<u8> {
        self.maybe_rotate();
        let epoch = self.epoch();
        let mac = Self::compute_mac(&self.curr_secret, client_ip, client_port, m1_prefix, epoch);

        let mut cookie = Vec::with_capacity(COOKIE_LEN);
        cookie.extend_from_slice(COOKIE_MAGIC);
        cookie.extend_from_slice(&epoch.to_be_bytes());
        cookie.extend_from_slice(&mac);
        cookie
    }

    /// Constant-time verification of an address-bound cookie against active epochs.
    pub fn verify_cookie(
        &mut self,
        cookie: &[u8],
        client_ip: &str,
        client_port: u16,
        m1_prefix: &[u8],
    ) -> bool {
        if cookie.len() != COOKIE_LEN {
            return false;
        }
        if cookie[..6].ct_eq(COOKIE_MAGIC).unwrap_u8() != 1 {
            return false;
        }

        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&cookie[6..14]);
        let epoch = u64::from_be_bytes(epoch_bytes);

        let curr_epoch = self.epoch();
        let diff = (epoch as i64).saturating_sub(curr_epoch as i64).abs();
        if diff > 1 {
            return false;
        }

        self.maybe_rotate();
        let candidate_mac = &cookie[14..38];

        let exp_curr =
            Self::compute_mac(&self.curr_secret, client_ip, client_port, m1_prefix, epoch);
        if candidate_mac.ct_eq(&exp_curr).unwrap_u8() == 1 {
            return true;
        }

        let exp_prev =
            Self::compute_mac(&self.prev_secret, client_ip, client_port, m1_prefix, epoch);
        candidate_mac.ct_eq(&exp_prev).unwrap_u8() == 1
    }

    /// Create a challenge packet containing `NPQ_CHALLENGE\0` || difficulty || cookie.
    pub fn create_challenge(
        &mut self,
        client_ip: &str,
        client_port: u16,
        m1_prefix: &[u8],
        difficulty_bits: u8,
    ) -> Vec<u8> {
        let diff = difficulty_bits.min(32);
        let cookie = self.create_cookie(client_ip, client_port, m1_prefix);

        let mut packet = Vec::with_capacity(CHALLENGE_PREFIX.len() + 1 + cookie.len());
        packet.extend_from_slice(CHALLENGE_PREFIX);
        packet.push(diff);
        packet.extend_from_slice(&cookie);
        packet
    }

    /// Verify a challenge response: cookie + 8-byte PoW nonce.
    /// Enforces single-use cache to prevent PoW solution replay.
    pub fn verify_response(
        &mut self,
        response: &[u8],
        client_ip: &str,
        client_port: u16,
        m1_prefix: &[u8],
        difficulty_bits: u8,
    ) -> bool {
        if response.len() != RESPONSE_LEN {
            return false;
        }

        let now = Self::now_secs();
        {
            let seen = match self.seen_solutions.lock() {
                Ok(g) => g,
                Err(_) => return false,
            };
            if seen.contains_key(response) {
                return false;
            }
        }

        let cookie = &response[..COOKIE_LEN];
        let nonce_bytes = &response[COOKIE_LEN..RESPONSE_LEN];

        if !self.verify_cookie(cookie, client_ip, client_port, m1_prefix) {
            return false;
        }

        if difficulty_bits > 0 {
            let mut hasher = Sha256::new();
            hasher.update(cookie);
            hasher.update(nonce_bytes);
            let h = hasher.finalize();
            let mut h_arr = [0u8; 32];
            h_arr.copy_from_slice(&h);

            if leading_zeros_256(&h_arr) < difficulty_bits as u32 {
                return false;
            }
        }

        // Cache solution to prevent replay
        if let Ok(mut seen) = self.seen_solutions.lock() {
            if seen.len() >= self.max_cached_solutions {
                let cutoff = now.saturating_sub(2 * self.rotation_interval);
                seen.retain(|_, &mut ts| ts >= cutoff);
            }
            seen.insert(response.to_vec(), now);
        }
        true
    }

    /// Client-side solver for cookie challenge with micro-Proof-of-Work.
    pub fn solve_challenge(challenge_payload: &[u8], max_iterations: u64) -> Option<Vec<u8>> {
        if !challenge_payload.starts_with(CHALLENGE_PREFIX) {
            return None;
        }
        let off = CHALLENGE_PREFIX.len();
        if challenge_payload.len() < off + 1 + COOKIE_LEN {
            return None;
        }
        let difficulty = challenge_payload[off];
        let cookie = &challenge_payload[off + 1..off + 1 + COOKIE_LEN];

        if difficulty == 0 {
            let mut resp = Vec::with_capacity(RESPONSE_LEN);
            resp.extend_from_slice(cookie);
            resp.extend_from_slice(&0u64.to_be_bytes());
            return Some(resp);
        }

        let mut nonce = 0u64;
        let mut hasher = Sha256::new();
        while nonce < max_iterations {
            let nb = nonce.to_be_bytes();
            hasher.update(cookie);
            hasher.update(nb);
            let h = hasher.finalize_reset();
            let mut h_arr = [0u8; 32];
            h_arr.copy_from_slice(&h);

            if leading_zeros_256(&h_arr) >= difficulty as u32 {
                let mut resp = Vec::with_capacity(RESPONSE_LEN);
                resp.extend_from_slice(cookie);
                resp.extend_from_slice(&nb);
                return Some(resp);
            }
            nonce += 1;
        }
        None
    }

    /// Ingress filter for incoming M1 frames over connectionless transport.
    /// Returns:
    ///     ("ACCEPT", m1_bytes) — proceed to responder_reply
    ///     ("CHALLENGE", challenge_packet) — transmit challenge back to client
    ///     ("DROP", []) — invalid, oversize, or spoofed; drop silently
    pub fn process_incoming_m1(
        &mut self,
        wire: &[u8],
        client_ip: &str,
        client_port: u16,
        require_cookie: bool,
        difficulty_bits: u8,
    ) -> (&'static str, Vec<u8>) {
        let (solution_opt, m1) = unpack_cookie_m1(wire);
        if m1.len() != EXPECTED_M1_LEN {
            return ("DROP", Vec::new());
        }
        if !require_cookie && solution_opt.is_none() {
            return ("ACCEPT", m1.to_vec());
        }
        match solution_opt {
            None => {
                let pfx = if m1.len() >= 64 { &m1[..64] } else { m1 };
                let chal = self.create_challenge(client_ip, client_port, pfx, difficulty_bits);
                ("CHALLENGE", chal)
            }
            Some(sol) => {
                let pfx = if m1.len() >= 64 { &m1[..64] } else { m1 };
                if self.verify_response(sol, client_ip, client_port, pfx, difficulty_bits) {
                    ("ACCEPT", m1.to_vec())
                } else {
                    ("DROP", Vec::new())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_generation_and_verification() {
        let mut gate = StatelessCookieGate::new(120, 1024);
        let ip = "192.168.1.50";
        let port = 51820;
        let pfx = b"sample_m1_prefix_bytes_test_data";

        let cookie = gate.create_cookie(ip, port, pfx);
        assert_eq!(cookie.len(), COOKIE_LEN);
        assert!(gate.verify_cookie(&cookie, ip, port, pfx));

        // Wrong IP fails
        assert!(!gate.verify_cookie(&cookie, "192.168.1.51", port, pfx));
        // Wrong port fails
        assert!(!gate.verify_cookie(&cookie, ip, 51821, pfx));
        // Wrong prefix fails
        assert!(!gate.verify_cookie(&cookie, ip, port, b"other_prefix"));
        // Tampered cookie fails
        let mut bad = cookie.clone();
        bad[20] ^= 0x01;
        assert!(!gate.verify_cookie(&bad, ip, port, pfx));
    }

    #[test]
    fn test_challenge_solve_and_verify() {
        let mut gate = StatelessCookieGate::new(120, 1024);
        let ip = "10.0.0.1";
        let port = 4433;
        let pfx = b"m1_init_bytes";

        let challenge = gate.create_challenge(ip, port, pfx, 4);
        let solution = StatelessCookieGate::solve_challenge(&challenge, 100_000).expect("solved");

        assert_eq!(solution.len(), RESPONSE_LEN);
        assert!(gate.verify_response(&solution, ip, port, pfx, 4));

        // Replay rejected
        assert!(!gate.verify_response(&solution, ip, port, pfx, 4));
    }

    #[test]
    fn test_zero_difficulty_challenge() {
        let mut gate = StatelessCookieGate::new(120, 1024);
        let ip = "127.0.0.1";
        let port = 9000;
        let pfx = b"prefix";

        let challenge = gate.create_challenge(ip, port, pfx, 0);
        let solution = StatelessCookieGate::solve_challenge(&challenge, 1000).expect("solved");
        assert!(gate.verify_response(&solution, ip, port, pfx, 0));
    }
}
