//! Authenticated frame layout (all multi-byte fields big-endian):
//! `[seq: u64 | len: u16 | ftype: u8 | ciphertext: len bytes | tag: 16 bytes]`
//! The Poly1305 tag covers header + ciphertext. Anything failing the tag,
//! arriving pre-handshake, or malformed is dropped before parsing — never answered.

/// Frame type bytes on the wire.
pub const FTYPE_MSG: u8 = 0x01;
/// Chaff / heartbeat replacement. Never surfaces to the application.
pub const FTYPE_CHAFF: u8 = 0xFF;

/// Fixed framing quanta: TOTAL on-wire frame sizes in bytes (what an
/// adversary observes). 1232 = 1280 (IPv6 minimum MTU) − 40 (IPv6) − 8 (UDP).
/// Payload capacity at the largest quantum = 1232 − FRAME_OVERHEAD.
pub const FRAME_QUANTA: [usize; 3] = [256, 512, 1232];

/// Total on-wire overhead per frame: seq(8) + len(2) + type(1) + tag(16).
pub const FRAME_OVERHEAD: usize = 8 + 2 + 1 + 16;

/// Largest user payload that fits the largest quantum.
pub const MAX_PAYLOAD: usize = 1232 - FRAME_OVERHEAD; // 1205

/// Quantize a TOTAL frame size (payload + overhead) up to the next quantum.
/// Returns None when even the largest quantum cannot hold the frame.
pub fn quantize(total_len: usize) -> Option<usize> {
    FRAME_QUANTA.iter().copied().find(|&q| q >= total_len)
}

/// Pad a payload length to its quantum: returns (quantum, pad_bytes).
pub fn pad_to_quantum(payload_len: usize) -> Option<(usize, usize)> {
    let total = payload_len.checked_add(FRAME_OVERHEAD)?;
    quantize(total).map(|q| (q, q - total))
}

/// Maximum user payload per frame. Larger messages MUST be split with
/// [`split_payload`] and reassembled in sequence order on receipt
/// (sequence numbers already order frames; no extra header needed).
pub const CHUNK_MAX: usize = MAX_PAYLOAD;

/// Split an arbitrarily large payload into `CHUNK_MAX`-sized pieces.
/// Empty payload yields zero chunks (callers send a single empty frame).
pub fn split_payload(payload: &[u8]) -> Vec<Vec<u8>> {
    payload.chunks(CHUNK_MAX).map(|c| c.to_vec()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quanta_cover_expected_sizes() {
        // quantize() takes TOTAL frame size (payload + 27B overhead).
        assert_eq!(quantize(27), Some(256)); // empty payload frame
        assert_eq!(quantize(256), Some(256));
        assert_eq!(quantize(257), Some(512));
        assert_eq!(quantize(1232), Some(1232));
        assert_eq!(quantize(1233), None);
        // Payload-level helper: 1205B payload exactly fills the top quantum.
        assert_eq!(pad_to_quantum(1205), Some((1232, 0)));
        assert_eq!(pad_to_quantum(0), Some((256, 256 - FRAME_OVERHEAD)));
        assert_eq!(pad_to_quantum(1206), None);
    }

    #[test]
    fn ipv6_budget_math_holds() {
        // Largest quantum fits the IPv6 minimum MTU exactly.
        assert_eq!(1232 + 40 + 8, 1280);
        assert_eq!(MAX_PAYLOAD + FRAME_OVERHEAD, 1232);
    }

    #[test]
    fn chunk_boundaries_exact() {
        assert!(split_payload(&[]).is_empty());
        assert_eq!(split_payload(&[1u8; 1205]).len(), 1);
        assert_eq!(split_payload(&[1u8; 1206]).len(), 2);
        let chunks = split_payload(&[2u8; 2410]);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), CHUNK_MAX);
        assert_eq!(chunks[1].len(), CHUNK_MAX);
        // Reassembly is plain concatenation in sequence order.
        let mut joined = Vec::new();
        for c in split_payload(&[3u8; 5000]) {
            joined.extend_from_slice(&c);
        }
        assert_eq!(joined, vec![3u8; 5000]);
    }
}
