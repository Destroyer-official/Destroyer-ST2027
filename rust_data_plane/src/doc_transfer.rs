//! Sensitive Military Document Transfer with Post-Quantum SHA-384 Integrity.
//!
//! Encapsulates files into in-band tactical document streams that travel securely across
//! the zero-gap pipeline and paced cells, verified via SHA-384 against data tampering.

use sha2::{Digest, Sha384};
use crate::policy::CoreError;

/// Document transfer metadata envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocTransferMeta {
    pub filename: String,
    pub size_bytes: usize,
    pub sha384_hex: String,
}

/// Helper hex encode
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Base64 helper
const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
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

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    let trimmed = input.trim_end_matches('=');
    let bytes = trimmed.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = base64_val(bytes[i])?;
        let b1 = if i + 1 < bytes.len() { base64_val(bytes[i + 1])? } else { 0 };
        let b2 = if i + 2 < bytes.len() { base64_val(bytes[i + 2])? } else { 0 };
        let b3 = if i + 3 < bytes.len() { base64_val(bytes[i + 3])? } else { 0 };

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

/// Compute SHA-384 integrity digest as lowercase hex string.
pub fn compute_sha384_hex(content: &[u8]) -> String {
    let mut hasher = Sha384::new();
    hasher.update(content);
    let digest = hasher.finalize();
    hex_encode(&digest)
}

/// Package a file into a wire document transfer payload:
/// `DOC:<filename>:<sha384_hex>:<base64_content>`
pub fn package_document(filename: &str, content: &[u8]) -> (DocTransferMeta, Vec<u8>) {
    let sha384_hex = compute_sha384_hex(content);
    let b64_content = base64_encode(content);
    let payload = format!("DOC:{}:{}:{}", filename, sha384_hex, b64_content).into_bytes();

    let meta = DocTransferMeta {
        filename: filename.to_string(),
        size_bytes: content.len(),
        sha384_hex,
    };
    (meta, payload)
}

/// Unpack and verify an inbound document payload:
/// Verifies the SHA-384 digest matches the reconstructed payload fail-closed.
pub fn unpack_and_verify_document(payload: &[u8]) -> Result<(DocTransferMeta, Vec<u8>), CoreError> {
    let s = core::str::from_utf8(payload).map_err(|_| CoreError::Malformed)?;
    if !s.starts_with("DOC:") {
        return Err(CoreError::Malformed);
    }

    let parts: Vec<&str> = s.splitn(4, ':').collect();
    if parts.len() < 4 {
        return Err(CoreError::Malformed);
    }

    let filename = parts[1].to_string();
    let expected_sha384 = parts[2].trim().to_lowercase();
    let b64_data = parts[3];

    let content = base64_decode(b64_data).map_err(|_| CoreError::Malformed)?;
    let actual_sha384 = compute_sha384_hex(&content);

    // Constant-time check on SHA-384 hash hex string
    if !crate::ct::ct_eq(actual_sha384.as_bytes(), expected_sha384.as_bytes()) {
        return Err(CoreError::BadSignature);
    }

    let meta = DocTransferMeta {
        filename,
        size_bytes: content.len(),
        sha384_hex: actual_sha384,
    };

    Ok((meta, content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_and_unpack_roundtrip() {
        let content = b"TOP SECRET // OPERATION OMEGA TACTICAL FLIGHT PLAN // DEFCON-1";
        let (meta, wire) = package_document("flight_plan.pdf", content);
        assert_eq!(meta.filename, "flight_plan.pdf");
        assert_eq!(meta.size_bytes, content.len());

        let (meta2, unpacked) = unpack_and_verify_document(&wire).expect("unpack");
        assert_eq!(meta2, meta);
        assert_eq!(unpacked, content);
    }

    #[test]
    fn tampered_document_fails_verification() {
        let content = b"GENUINE MILITARY DIRECTIVE";
        let (_meta, wire) = package_document("order.txt", content);

        let mut tampered = wire.clone();
        tampered.push(b'A'); // Corrupt payload

        assert!(unpack_and_verify_document(&tampered).is_err());
    }
}
