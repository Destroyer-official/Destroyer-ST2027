//! ZGDP_FRAG fragmentation and reassembly protocol.
//!
//! Splits large cryptographic payloads into quantum-sized chunks for transmission
//! over paced channels with anti-leak padding and bounded assembly buffers.
//!
//! Provides both binary wire serialization (12-byte header) and text-line
//! interoperability with the legacy Python channel line discipline:
//! `ZGDP_FRAG:<tx_id_hex>:<index>:<total>:<base64_data>`

use crate::policy::CoreError;

/// Default fragment chunk size (matches Python CHUNK_SIZE = 600 bytes).
pub const DEFAULT_CHUNK_SIZE: usize = 600;

/// Maximum allowable fragments per transaction (bounds allocation to prevent DoS).
pub const MAX_FRAGMENTS: usize = 4096;

/// Transaction ID length in bytes.
pub const TX_ID_LEN: usize = 8;

/// Wire header overhead: 8 bytes tx_id + 2 bytes index + 2 bytes total = 12 bytes.
pub const FRAGMENT_HEADER_LEN: usize = TX_ID_LEN + 2 + 2;

/// A self-describing transaction fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub tx_id: [u8; TX_ID_LEN],
    pub index: u16,
    pub total: u16,
    pub data: Vec<u8>,
}

impl Fragment {
    /// Serialize to 12-byte binary wire frame:
    /// `[tx_id: 8B][index: 2B BE][total: 2B BE][data: variable]`
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAGMENT_HEADER_LEN + self.data.len());
        out.extend_from_slice(&self.tx_id);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Parse from binary wire frame.
    pub fn from_wire(wire: &[u8]) -> Result<Self, CoreError> {
        if wire.len() < FRAGMENT_HEADER_LEN {
            return Err(CoreError::Malformed);
        }
        let mut tx_id = [0u8; TX_ID_LEN];
        tx_id.copy_from_slice(&wire[..TX_ID_LEN]);

        let idx_b: [u8; 2] = wire[8..10].try_into().map_err(|_| CoreError::Malformed)?;
        let index = u16::from_be_bytes(idx_b);

        let tot_b: [u8; 2] = wire[10..12].try_into().map_err(|_| CoreError::Malformed)?;
        let total = u16::from_be_bytes(tot_b);

        if total == 0 || total as usize > MAX_FRAGMENTS || index >= total {
            return Err(CoreError::Malformed);
        }

        let data = wire[FRAGMENT_HEADER_LEN..].to_vec();
        Ok(Self {
            tx_id,
            index,
            total,
            data,
        })
    }

    /// Format as text line for ASCII/Paced Channel stdin/stdout interop:
    /// `ZGDP_FRAG:<tx_id_hex>:<index>:<total>:<base64_data>\n`
    pub fn to_text_line(&self) -> String {
        let tx_hex = hex_encode(&self.tx_id);
        let b64 = base64_sim_encode(&self.data);
        format!(
            "ZGDP_FRAG:{}:{}:{}:{}\n",
            tx_hex, self.index, self.total, b64
        )
    }

    /// Parse from ASCII line `ZGDP_FRAG:<tx_id_hex>:<index>:<total>:<base64_data>`.
    pub fn from_text_line(line: &str) -> Result<Self, CoreError> {
        let trimmed = line.trim();
        if !trimmed.starts_with("ZGDP_FRAG:") {
            return Err(CoreError::Malformed);
        }
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() < 5 {
            return Err(CoreError::Malformed);
        }
        let tx_bytes = hex_decode(parts[1]).map_err(|_| CoreError::Malformed)?;
        if tx_bytes.len() != TX_ID_LEN {
            return Err(CoreError::Malformed);
        }
        let mut tx_id = [0u8; TX_ID_LEN];
        tx_id.copy_from_slice(&tx_bytes);

        let index: u16 = parts[2].parse().map_err(|_| CoreError::Malformed)?;
        let total: u16 = parts[3].parse().map_err(|_| CoreError::Malformed)?;

        if total == 0 || total as usize > MAX_FRAGMENTS || index >= total {
            return Err(CoreError::Malformed);
        }

        let data = base64_sim_decode(parts[4]).map_err(|_| CoreError::Malformed)?;
        Ok(Self {
            tx_id,
            index,
            total,
            data,
        })
    }
}

/// Split payload into bounded fragments of `chunk_size` bytes each.
pub fn fragment(payload: &[u8], chunk_size: usize) -> Result<Vec<Fragment>, CoreError> {
    if chunk_size == 0 {
        return Err(CoreError::Malformed);
    }

    let total = if payload.is_empty() {
        1
    } else {
        payload.len().div_ceil(chunk_size)
    };

    if total > MAX_FRAGMENTS {
        return Err(CoreError::Oversize);
    }

    let mut tx_id = [0u8; TX_ID_LEN];
    getrandom::fill(&mut tx_id).map_err(|_| CoreError::OsRandom)?;

    let mut fragments = Vec::with_capacity(total);
    if payload.is_empty() {
        fragments.push(Fragment {
            tx_id,
            index: 0,
            total: 1,
            data: Vec::new(),
        });
        return Ok(fragments);
    }

    for (idx, chunk) in payload.chunks(chunk_size).enumerate() {
        fragments.push(Fragment {
            tx_id,
            index: idx as u16,
            total: total as u16,
            data: chunk.to_vec(),
        });
    }

    Ok(fragments)
}

/// In-flight transaction reassembly buffer.
#[derive(Debug, Clone)]
pub struct ReassemblyBuffer {
    tx_id: [u8; TX_ID_LEN],
    total: u16,
    received_count: usize,
    slots: Vec<Option<Vec<u8>>>,
}

impl ReassemblyBuffer {
    /// Create a new reassembly buffer for a specific transaction ID.
    pub fn new(tx_id: [u8; TX_ID_LEN], total: u16) -> Result<Self, CoreError> {
        if total == 0 || total as usize > MAX_FRAGMENTS {
            return Err(CoreError::Malformed);
        }
        let total_usize = total as usize;
        let mut slots = Vec::with_capacity(total_usize);
        slots.resize_with(total_usize, || None);

        Ok(Self {
            tx_id,
            total,
            received_count: 0,
            slots,
        })
    }

    /// Insert an inbound fragment into the buffer.
    ///
    /// Returns `Ok(true)` if this fragment completed the assembly.
    /// Returns `Ok(false)` if more fragments are needed.
    /// Returns `Err(CoreError)` if the fragment is malformed, from another transaction, or duplicated.
    pub fn insert(&mut self, frag: Fragment) -> Result<bool, CoreError> {
        if frag.tx_id != self.tx_id || frag.total != self.total {
            return Err(CoreError::Malformed);
        }
        let idx = frag.index as usize;
        if idx >= self.slots.len() {
            return Err(CoreError::Malformed);
        }
        if self.slots[idx].is_some() {
            // Duplicate fragment rejected fail-closed
            return Err(CoreError::Malformed);
        }

        self.slots[idx] = Some(frag.data);
        self.received_count += 1;

        Ok(self.is_complete())
    }

    /// Check if all fragments have arrived.
    pub fn is_complete(&self) -> bool {
        self.received_count == self.total as usize
    }

    /// Reassemble all collected fragments in sequence.
    pub fn reassemble(&self) -> Result<Vec<u8>, CoreError> {
        if !self.is_complete() {
            return Err(CoreError::Malformed);
        }
        let total_bytes: usize = self
            .slots
            .iter()
            .map(|s| s.as_ref().map(|d| d.len()).unwrap_or(0))
            .sum();

        let mut out = Vec::with_capacity(total_bytes);
        for s in &self.slots {
            match s {
                Some(chunk) => out.extend_from_slice(chunk),
                None => return Err(CoreError::Malformed),
            }
        }
        Ok(out)
    }

    pub fn tx_id(&self) -> [u8; TX_ID_LEN] {
        self.tx_id
    }

    pub fn received_count(&self) -> usize {
        self.received_count
    }

    pub fn total(&self) -> u16 {
        self.total
    }
}

// ---------------------------------------------------------------------------
// Helpers: Hex & Base64 conversions without external crate bloat
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let b = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ())?;
        out.push(b);
    }
    Ok(out)
}

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_sim_encode(input: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };

        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        out.push(B64_CHARS[((n >> 18) & 63) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 63) as usize] as char);

        if i + 1 < input.len() {
            out.push(B64_CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }

        if i + 2 < input.len() {
            out.push(B64_CHARS[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }

        i += 3;
    }
    out
}

fn base64_val(c: u8) -> Result<u32, ()> {
    match c {
        b'A'..=b'Z' => Ok((c - b'A') as u32),
        b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
        b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(()),
    }
}

fn base64_sim_decode(input: &str) -> Result<Vec<u8>, ()> {
    let trimmed = input.trim_end_matches('=');
    let bytes = trimmed.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = base64_val(bytes[i])?;
        let b1 = if i + 1 < bytes.len() {
            base64_val(bytes[i + 1])?
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            base64_val(bytes[i + 2])?
        } else {
            0
        };
        let b3 = if i + 3 < bytes.len() {
            base64_val(bytes[i + 3])?
        } else {
            0
        };

        let n = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;

        out.push(((n >> 16) & 0xFF) as u8);
        if i + 2 < bytes.len() {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if i + 3 < bytes.len() {
            out.push((n & 0xFF) as u8);
        }

        i += 4;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_reassemble_roundtrip() {
        let payload = vec![0x42u8; 2500];
        let frags = fragment(&payload, 600).expect("fragment failed");
        assert_eq!(frags.len(), 5); // 600 * 4 + 100

        let mut buf = ReassemblyBuffer::new(frags[0].tx_id, frags[0].total).expect("buffer");
        for (i, f) in frags.into_iter().enumerate() {
            let done = buf.insert(f).expect("insert");
            if i == 4 {
                assert!(done);
            } else {
                assert!(!done);
            }
        }
        let reassembled = buf.reassemble().expect("reassemble");
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn single_chunk_and_empty() {
        let p_small = b"hello tactical world";
        let frags = fragment(p_small, 600).unwrap();
        assert_eq!(frags.len(), 1);

        let mut buf = ReassemblyBuffer::new(frags[0].tx_id, frags[0].total).unwrap();
        assert!(buf.insert(frags[0].clone()).unwrap());
        assert_eq!(buf.reassemble().unwrap(), p_small);

        let frags_empty = fragment(b"", 600).unwrap();
        assert_eq!(frags_empty.len(), 1);
        let mut buf_e = ReassemblyBuffer::new(frags_empty[0].tx_id, frags_empty[0].total).unwrap();
        assert!(buf_e.insert(frags_empty[0].clone()).unwrap());
        assert_eq!(buf_e.reassemble().unwrap(), b"");
    }

    #[test]
    fn wire_and_text_roundtrip() {
        let f = Fragment {
            tx_id: [1, 2, 3, 4, 5, 6, 7, 8],
            index: 2,
            total: 10,
            data: b"classified tactical coordinates".to_vec(),
        };

        // Binary wire
        let wire = f.to_wire();
        let f_parsed = Fragment::from_wire(&wire).expect("from_wire");
        assert_eq!(f, f_parsed);

        // Text line
        let line = f.to_text_line();
        let f_line = Fragment::from_text_line(&line).expect("from_text_line");
        assert_eq!(f, f_line);
    }

    #[test]
    fn duplicate_and_tampered_rejected() {
        let f = Fragment {
            tx_id: [1; 8],
            index: 0,
            total: 2,
            data: vec![0x11],
        };
        let mut buf = ReassemblyBuffer::new([1; 8], 2).unwrap();
        assert!(!buf.insert(f.clone()).unwrap());
        // Duplicate fails
        assert_eq!(buf.insert(f).unwrap_err(), CoreError::Malformed);

        // Wrong tx_id fails
        let wrong_f = Fragment {
            tx_id: [2; 8],
            index: 1,
            total: 2,
            data: vec![0x22],
        };
        assert_eq!(buf.insert(wrong_f).unwrap_err(), CoreError::Malformed);
    }
}
