//! Authenticated frame layout (all multi-byte fields big-endian):
//! `[seq: u64 | len: u16 | ftype: u8 | ciphertext: len bytes | tag: 16 bytes]`
//! The GHASH tag covers header + ciphertext. Anything failing the tag,
//! arriving pre-handshake, or malformed is dropped before parsing — never answered.

use crate::policy::CoreError;

/// Frame type bytes on the wire.
pub const FTYPE_MSG: u8 = 0x01;
/// In-band Continuous Epoch Ratchet (CER) rekeying envelope (FTYPE_REKEY = 0x02).
pub const FTYPE_REKEY: u8 = 0x02;
/// Attestation evidence envelope (carrying post-quantum RFC 9881 certificate chains / attestation evidence).
pub const FTYPE_ATTESTATION_EVIDENCE: u8 = 0x05;
/// In-band threshold Certificate Revocation List (CRL) broadcast.
pub const FTYPE_REVOCATION: u8 = 0x06;
/// In-band Continuous Epoch Ratchet (CER) key replenishment frame (FTYPE_IN_BAND_EPOCH_REKEY = 0x07).
pub const FTYPE_IN_BAND_EPOCH_REKEY: u8 = 0x07;
/// Alias matching specification name: IN_BAND_EPOCH_REKEY = 0x07.
pub const IN_BAND_EPOCH_REKEY: u8 = 0x07;
/// Chaff / heartbeat replacement. Never surfaces to the application.
pub const FTYPE_CHAFF: u8 = 0xFF;

/// In-Band Epoch Rekey payload format constants:
/// Payload format:
/// `EpochIndex (u32 BE) || Ephemeral_P384_Pub (97B) || Ephemeral_MLKEM_CT (1568B) || Next_P384_Pub (97B) || Next_MLKEM_EK (1568B) || AuthTag (32B)`
pub const EPOCH_INDEX_LEN: usize = 4;
pub const P384_PK_WIRE_LEN: usize = 97;
pub const MLKEM1024_CT_LEN: usize = 1568;
pub const MLKEM1024_EK_WIRE_LEN: usize = 1568;
pub const AUTH_TAG_32_LEN: usize = 32;
pub const MLDSA87_SIG_WIRE_LEN: usize = 4627;
pub const AUTH_TAG_16_LEN: usize = 16; // preserved constant alias for external references
pub const IN_BAND_REKEY_PAYLOAD_LEN: usize = EPOCH_INDEX_LEN
    + P384_PK_WIRE_LEN
    + MLKEM1024_CT_LEN
    + P384_PK_WIRE_LEN
    + MLKEM1024_EK_WIRE_LEN
    + AUTH_TAG_32_LEN; // 3366 bytes
pub const IN_BAND_REKEY_AUTH_PAYLOAD_LEN: usize = IN_BAND_REKEY_PAYLOAD_LEN + MLDSA87_SIG_WIRE_LEN; // 7993 bytes

/// Wire representation of a hybrid Continuous Epoch Ratchet (CER) rekey payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InBandEpochRekeyPayload {
    /// Monotonic epoch index (32-bit big-endian).
    pub epoch: u32,
    /// Fresh ephemeral P-384 ECDHE share (97 bytes uncompressed SEC1).
    pub eph_p_pub: [u8; P384_PK_WIRE_LEN],
    /// Fresh ephemeral ML-KEM-1024 ciphertext (1568 bytes, FIPS 203).
    pub ct: [u8; MLKEM1024_CT_LEN],
    /// Sender's rotated next P-384 public key for consecutive epochs (97 bytes).
    pub next_p_pub: [u8; P384_PK_WIRE_LEN],
    /// Sender's rotated next ML-KEM-1024 encapsulation key (1568 bytes).
    pub next_ek: [u8; MLKEM1024_EK_WIRE_LEN],
    /// 32-byte HMAC-SHA384 authentication tag covering all preceding fields under domain-separated root key.
    pub tag: [u8; AUTH_TAG_32_LEN],
    /// Optional 4627-byte ML-DSA-87 signature binding long-term peer identity (mandatory in production/identity mode).
    pub mldsa_sig: Option<Vec<u8>>,
}

impl InBandEpochRekeyPayload {
    pub fn new(
        epoch: u32,
        eph_p_pub: [u8; P384_PK_WIRE_LEN],
        ct: [u8; MLKEM1024_CT_LEN],
        next_p_pub: [u8; P384_PK_WIRE_LEN],
        next_ek: [u8; MLKEM1024_EK_WIRE_LEN],
        tag: [u8; AUTH_TAG_32_LEN],
    ) -> Self {
        Self {
            epoch,
            eph_p_pub,
            ct,
            next_p_pub,
            next_ek,
            tag,
            mldsa_sig: None,
        }
    }

    pub fn with_signature(mut self, sig: Vec<u8>) -> Result<Self, CoreError> {
        if sig.len() != MLDSA87_SIG_WIRE_LEN {
            return Err(CoreError::Malformed);
        }
        self.mldsa_sig = Some(sig);
        Ok(self)
    }

    /// Serialize body + tag (3366B base) and append ML-DSA-87 signature (4627B) if attached.
    pub fn to_vec(&self) -> Vec<u8> {
        let base = self.to_bytes();
        match self.mldsa_sig {
            Some(ref sig) => {
                let mut out = Vec::with_capacity(IN_BAND_REKEY_PAYLOAD_LEN + sig.len());
                out.extend_from_slice(&base);
                out.extend_from_slice(sig);
                out
            }
            None => base.to_vec(),
        }
    }

    /// Serialize base payload (without optional ML-DSA-87 trailer) to 3366-byte buffer.
    pub fn to_bytes(&self) -> [u8; IN_BAND_REKEY_PAYLOAD_LEN] {
        let mut out = [0u8; IN_BAND_REKEY_PAYLOAD_LEN];
        let mut off = 0;
        out[off..off + 4].copy_from_slice(&self.epoch.to_be_bytes());
        off += 4;
        out[off..off + P384_PK_WIRE_LEN].copy_from_slice(&self.eph_p_pub);
        off += P384_PK_WIRE_LEN;
        out[off..off + MLKEM1024_CT_LEN].copy_from_slice(&self.ct);
        off += MLKEM1024_CT_LEN;
        out[off..off + P384_PK_WIRE_LEN].copy_from_slice(&self.next_p_pub);
        off += P384_PK_WIRE_LEN;
        out[off..off + MLKEM1024_EK_WIRE_LEN].copy_from_slice(&self.next_ek);
        off += MLKEM1024_EK_WIRE_LEN;
        out[off..].copy_from_slice(&self.tag);
        out
    }

    /// Parse and validate payload from binary slice (accepts 3366B base or 7993B ML-DSA-87 authenticated payload).
    pub fn from_bytes(slice: &[u8]) -> Result<Self, CoreError> {
        if slice.len() != IN_BAND_REKEY_PAYLOAD_LEN && slice.len() != IN_BAND_REKEY_AUTH_PAYLOAD_LEN
        {
            return Err(CoreError::Malformed);
        }
        let mut off = 0;
        let epoch = u32::from_be_bytes(
            slice[off..off + 4]
                .try_into()
                .map_err(|_| CoreError::Malformed)?,
        );
        off += 4;
        let mut eph_p_pub = [0u8; P384_PK_WIRE_LEN];
        eph_p_pub.copy_from_slice(&slice[off..off + P384_PK_WIRE_LEN]);
        off += P384_PK_WIRE_LEN;
        let mut ct = [0u8; MLKEM1024_CT_LEN];
        ct.copy_from_slice(&slice[off..off + MLKEM1024_CT_LEN]);
        off += MLKEM1024_CT_LEN;
        let mut next_p_pub = [0u8; P384_PK_WIRE_LEN];
        next_p_pub.copy_from_slice(&slice[off..off + P384_PK_WIRE_LEN]);
        off += P384_PK_WIRE_LEN;
        let mut next_ek = [0u8; MLKEM1024_EK_WIRE_LEN];
        next_ek.copy_from_slice(&slice[off..off + MLKEM1024_EK_WIRE_LEN]);
        off += MLKEM1024_EK_WIRE_LEN;
        let mut tag = [0u8; AUTH_TAG_32_LEN];
        tag.copy_from_slice(&slice[off..off + AUTH_TAG_32_LEN]);
        off += AUTH_TAG_32_LEN;
        let mldsa_sig = if slice.len() == IN_BAND_REKEY_AUTH_PAYLOAD_LEN {
            Some(slice[off..].to_vec())
        } else {
            None
        };
        Ok(Self {
            epoch,
            eph_p_pub,
            ct,
            next_p_pub,
            next_ek,
            tag,
            mldsa_sig,
        })
    }
}

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
    #[test]
    fn in_band_epoch_rekey_payload_roundtrip() {
        let eph_p = [0x11u8; P384_PK_WIRE_LEN];
        let mut ct = [0u8; MLKEM1024_CT_LEN];
        ct[0] = 0xAA;
        ct[MLKEM1024_CT_LEN - 1] = 0x55;
        let next_p = [0x22u8; P384_PK_WIRE_LEN];
        let next_ek = [0x33u8; MLKEM1024_EK_WIRE_LEN];
        let mut tag = [0u8; AUTH_TAG_32_LEN];
        tag[0] = 0x12;
        tag[AUTH_TAG_32_LEN - 1] = 0x34;

        let payload = InBandEpochRekeyPayload::new(42, eph_p, ct, next_p, next_ek, tag);
        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), IN_BAND_REKEY_PAYLOAD_LEN);
        assert_eq!(&bytes[..4], &42u32.to_be_bytes());
        assert_eq!(&bytes[4..4 + P384_PK_WIRE_LEN], &eph_p);
        assert_eq!(
            &bytes[4 + P384_PK_WIRE_LEN..4 + P384_PK_WIRE_LEN + MLKEM1024_CT_LEN],
            &ct
        );

        let parsed = InBandEpochRekeyPayload::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, payload);

        // Malformed lengths fail-closed
        assert_eq!(
            InBandEpochRekeyPayload::from_bytes(&bytes[..1000]),
            Err(CoreError::Malformed)
        );
        let mut oversize = bytes.to_vec();
        oversize.push(0x00);
        assert_eq!(
            InBandEpochRekeyPayload::from_bytes(&oversize),
            Err(CoreError::Malformed)
        );
    }
}
