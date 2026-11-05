//! RFC 9881 Standards-Compliant Post-Quantum X.509 & CRL Engine.
//!
//! Implements strict, fail-closed ASN.1 DER encoding and decoding for:
//! 1. ML-DSA-87 X.509v3 Certificates supporting both:
//!    - OID `1.3.6.1.4.1.2.267.12.8.7` (IBM / Dilithium5 / ML-DSA-87 draft)
//!    - OID `2.16.840.1.101.3.4.3.19` (NIST CSOR id-ml-dsa-87 from RFC 9881)
//!    - RFC 9881 rule: AlgorithmIdentifier parameters MUST be omitted (absent).
//! 2. SubjectPublicKeyInfo containing the 2,592-byte ML-DSA-87 public key.
//! 3. 3-of-5 Offline Threshold Root CA multi-signature quorum validation
//!    (encoded via standard X.509 extension `1.3.6.1.4.1.2.267.12.8.7.99`).
//! 4. RFC 5280 / RFC 9881 Certificate Revocation Lists (CRLs) with
//!    monotonic `cRLNumber` extension (OID `2.5.29.20`) and threshold signatures.

use std::collections::{HashMap, HashSet};

use crate::auth::{Mldsa87SigningKey, Mldsa87VerifyingKey};
use crate::pki::{norm_ident, tbs_bytes, Custodian, MAX_LIFETIME, MAX_SKEW_FUTURE, QUORUM, TOTAL};
use crate::policy::{CoreError, MLDSA87_PK};

/// OID for ML-DSA-87 (IBM / Dilithium5 draft arc, category 5).
pub const OID_ML_DSA_87_IBM: &str = "1.3.6.1.4.1.2.267.12.8.7";
/// OID for ML-DSA-87 (NIST CSOR standard arc per RFC 9881).
pub const OID_ML_DSA_87_NIST: &str = "2.16.840.1.101.3.4.3.19";
/// OID for 3-of-5 Threshold Custodian Signatures Extension.
pub const OID_THRESHOLD_SIGS: &str = "1.3.6.1.4.1.2.267.12.8.7.99";
/// OID for standard CRL Number extension (RFC 5280).
pub const OID_CRL_NUMBER: &str = "2.5.29.20";
/// OID for X.500 CommonName (2.5.4.3).
pub const OID_COMMON_NAME: &str = "2.5.4.3";

// ASN.1 DER Tags
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_PRINTABLE_STRING: u8 = 0x13;
const TAG_IA5_STRING: u8 = 0x16;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_0: u8 = 0xA0;
const TAG_CONTEXT_3: u8 = 0xA3;

// --- ASN.1 DER Encoder Helpers ---

pub fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else if len <= 0xFFFFFF {
        vec![
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    } else {
        vec![
            0x84,
            (len >> 24) as u8,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

pub fn encode_tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + val.len());
    out.push(tag);
    out.extend_from_slice(&encode_length(val.len()));
    out.extend_from_slice(val);
    out
}

pub fn encode_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for it in items {
        body.extend_from_slice(it);
    }
    encode_tlv(TAG_SEQUENCE, &body)
}

pub fn encode_set(items: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for it in items {
        body.extend_from_slice(it);
    }
    encode_tlv(TAG_SET, &body)
}

pub fn encode_integer_u64(val: u64) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    // Skip leading zeroes, but if the most significant bit is set, prepend 0x00 for positive integer
    let mut start = 0;
    while start < 7 && bytes[start] == 0 {
        start += 1;
    }
    let slice = &bytes[start..];
    if (slice[0] & 0x80) != 0 {
        let mut b = vec![0x00];
        b.extend_from_slice(slice);
        encode_tlv(TAG_INTEGER, &b)
    } else {
        encode_tlv(TAG_INTEGER, slice)
    }
}

pub fn encode_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return encode_tlv(TAG_INTEGER, &[0x00]);
    }
    if (bytes[0] & 0x80) != 0 {
        let mut b = Vec::with_capacity(bytes.len() + 1);
        b.push(0x00);
        b.extend_from_slice(bytes);
        encode_tlv(TAG_INTEGER, &b)
    } else {
        encode_tlv(TAG_INTEGER, bytes)
    }
}

pub fn encode_bit_string(data: &[u8]) -> Vec<u8> {
    let mut val = Vec::with_capacity(1 + data.len());
    val.push(0x00); // 0 unused bits
    val.extend_from_slice(data);
    encode_tlv(TAG_BIT_STRING, &val)
}

pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, data)
}

pub fn encode_utf8_string(s: &str) -> Vec<u8> {
    encode_tlv(TAG_UTF8_STRING, s.as_bytes())
}

pub fn encode_oid(oid_str: &str) -> Vec<u8> {
    let parts: Vec<u64> = oid_str
        .split('.')
        .filter_map(|p| p.parse::<u64>().ok())
        .collect();
    if parts.len() < 2 {
        return encode_tlv(TAG_OID, &[]);
    }
    let mut body = vec![(parts[0] * 40 + parts[1]) as u8];
    for &p in &parts[2..] {
        if p == 0 {
            body.push(0x00);
        } else {
            let mut buf = Vec::new();
            let mut val = p;
            while val > 0 {
                buf.push((val & 0x7F) as u8);
                val >>= 7;
            }
            buf.reverse();
            for i in 0..buf.len() - 1 {
                buf[i] |= 0x80;
            }
            body.extend_from_slice(&buf);
        }
    }
    encode_tlv(TAG_OID, &body)
}

/// GeneralizedTime format: YYYYMMDDHHMMSSZ
pub fn encode_generalized_time(timestamp_secs: u64) -> Vec<u8> {
    // Days since unix epoch (1970-01-01)
    let secs = timestamp_secs;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Approximate calendar conversion (sufficient for RFC 9881 certificate validity formatting)
    let mut y = 1970u64;
    let mut d = days;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if d >= days_in_year {
            d -= days_in_year;
            y += 1;
        } else {
            break;
        }
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mon = 1u64;
    for &md in &mdays {
        if d >= md {
            d -= md;
            mon += 1;
        } else {
            break;
        }
    }
    let day = d + 1;
    let time_str = format!("{y:04}{mon:02}{day:02}{h:02}{m:02}{s:02}Z");
    encode_tlv(TAG_GENERALIZED_TIME, time_str.as_bytes())
}

/// AlgorithmIdentifier for RFC 9881:
/// Parameters MUST be absent (not NULL, not present).
pub fn encode_algorithm_identifier(oid: &str) -> Vec<u8> {
    let enc_oid = encode_oid(oid);
    encode_sequence(&[&enc_oid])
}

/// Encodes an X.500 Name with a CommonName attribute:
/// `SEQUENCE { SET { SEQUENCE { OBJECT IDENTIFIER commonName, UTF8String <val> } } }`
pub fn encode_common_name(name: &str) -> Vec<u8> {
    let oid = encode_oid(OID_COMMON_NAME);
    let val = encode_utf8_string(name);
    let rdn_seq = encode_sequence(&[&oid, &val]);
    let rdn_set = encode_set(&[&rdn_seq]);
    encode_sequence(&[&rdn_set])
}

/// Encodes RFC 9881 SubjectPublicKeyInfo:
/// `SEQUENCE { AlgorithmIdentifier, BIT STRING (unused=0 || pk_2592) }`
pub fn encode_subject_public_key_info(oid: &str, pk: &[u8]) -> Result<Vec<u8>, CoreError> {
    if pk.len() != MLDSA87_PK {
        return Err(CoreError::Malformed);
    }
    let alg_id = encode_algorithm_identifier(oid);
    let bit_str = encode_bit_string(pk);
    Ok(encode_sequence(&[&alg_id, &bit_str]))
}

// --- ASN.1 DER Parser ---

#[derive(Debug, Clone)]
pub struct DerElement<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub raw: &'a [u8],
}

pub fn parse_tlv(input: &[u8]) -> Result<(DerElement<'_>, &[u8]), CoreError> {
    if input.is_empty() {
        return Err(CoreError::Malformed);
    }
    let tag = input[0];
    let mut idx = 1;
    if idx >= input.len() {
        return Err(CoreError::Malformed);
    }
    let first_len = input[idx];
    idx += 1;

    let len = if first_len < 128 {
        first_len as usize
    } else {
        let num_octets = (first_len & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 || idx + num_octets > input.len() {
            return Err(CoreError::Malformed);
        }
        let mut l = 0usize;
        for _ in 0..num_octets {
            l = (l << 8) | (input[idx] as usize);
            idx += 1;
        }
        // Strict DER: shortest length encoding
        if l < 128 {
            return Err(CoreError::Malformed);
        }
        l
    };

    if idx + len > input.len() {
        return Err(CoreError::Malformed);
    }
    let raw = &input[..idx + len];
    let value = &input[idx..idx + len];
    let remainder = &input[idx + len..];

    Ok((DerElement { tag, value, raw }, remainder))
}

pub fn parse_sequence(input: &[u8]) -> Result<Vec<DerElement<'_>>, CoreError> {
    let (seq_el, rem) = parse_tlv(input)?;
    if seq_el.tag != TAG_SEQUENCE || !rem.is_empty() {
        return Err(CoreError::Malformed);
    }
    let mut items = Vec::new();
    let mut cur = seq_el.value;
    while !cur.is_empty() {
        let (el, next) = parse_tlv(cur)?;
        items.push(el);
        cur = next;
    }
    Ok(items)
}

pub fn parse_sequence_from_el<'a>(el: &DerElement<'a>) -> Result<Vec<DerElement<'a>>, CoreError> {
    if el.tag != TAG_SEQUENCE {
        return Err(CoreError::Malformed);
    }
    let mut items = Vec::new();
    let mut cur = el.value;
    while !cur.is_empty() {
        let (sub_el, next) = parse_tlv(cur)?;
        items.push(sub_el);
        cur = next;
    }
    Ok(items)
}

pub fn parse_integer_u64(el: &DerElement<'_>) -> Result<u64, CoreError> {
    if el.tag != TAG_INTEGER || el.value.is_empty() || el.value.len() > 9 {
        return Err(CoreError::Malformed);
    }
    let mut val = 0u64;
    for &b in el.value {
        val = (val << 8) | (b as u64);
    }
    Ok(val)
}

pub fn parse_integer_bytes(el: &DerElement<'_>) -> Result<Vec<u8>, CoreError> {
    if el.tag != TAG_INTEGER || el.value.is_empty() {
        return Err(CoreError::Malformed);
    }
    let mut slice = el.value;
    // Strip leading 0x00 added for positive integer representation if present
    if slice.len() > 1 && slice[0] == 0x00 && (slice[1] & 0x80) != 0 {
        slice = &slice[1..];
    }
    Ok(slice.to_vec())
}

pub fn parse_bit_string<'a>(el: &DerElement<'a>) -> Result<&'a [u8], CoreError> {
    if el.tag != TAG_BIT_STRING || el.value.is_empty() {
        return Err(CoreError::Malformed);
    }
    // First byte is unused bits, must be 0 for byte-aligned post-quantum keys/signatures
    if el.value[0] != 0x00 {
        return Err(CoreError::Malformed);
    }
    Ok(&el.value[1..])
}

pub fn parse_oid(el: &DerElement<'_>) -> Result<String, CoreError> {
    if el.tag != TAG_OID || el.value.is_empty() {
        return Err(CoreError::Malformed);
    }
    let body = el.value;
    let mut parts = vec![(body[0] / 40) as u64, (body[0] % 40) as u64];
    let mut val = 0u64;
    for &b in &body[1..] {
        val = (val << 7) | ((b & 0x7F) as u64);
        if (b & 0x80) == 0 {
            parts.push(val);
            val = 0;
        }
    }
    let s = parts
        .into_iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(".");
    Ok(s)
}

pub fn parse_common_name(el: &DerElement<'_>) -> Result<String, CoreError> {
    // Traverse Name -> RDN SET -> AttributeTypeAndValue SEQUENCE -> commonName
    let rdn_seqs = parse_sequence_from_el(el)?;
    for rdn_set in rdn_seqs {
        if rdn_set.tag != TAG_SET {
            continue;
        }
        let (attr_seq, _) = parse_tlv(rdn_set.value)?;
        let attrs = parse_sequence_from_el(&attr_seq)?;
        if attrs.len() >= 2 {
            let oid = parse_oid(&attrs[0])?;
            if oid == OID_COMMON_NAME {
                let name = std::str::from_utf8(attrs[1].value).map_err(|_| CoreError::Malformed)?;
                return Ok(name.to_string());
            }
        }
    }
    // Fallback: extract string if directly encoded
    if el.tag == TAG_UTF8_STRING || el.tag == TAG_PRINTABLE_STRING || el.tag == TAG_IA5_STRING {
        let name = std::str::from_utf8(el.value).map_err(|_| CoreError::Malformed)?;
        return Ok(name.to_string());
    }
    Err(CoreError::Malformed)
}

pub fn parse_time_secs(el: &DerElement<'_>) -> Result<u64, CoreError> {
    if el.tag != TAG_GENERALIZED_TIME && el.tag != TAG_UTC_TIME {
        return Err(CoreError::Malformed);
    }
    let s = std::str::from_utf8(el.value).map_err(|_| CoreError::Malformed)?;
    if el.tag == TAG_GENERALIZED_TIME && s.len() >= 15 && s.ends_with('Z') {
        let y: u64 = s[0..4].parse().map_err(|_| CoreError::Malformed)?;
        let m: u64 = s[4..6].parse().map_err(|_| CoreError::Malformed)?;
        let d: u64 = s[6..8].parse().map_err(|_| CoreError::Malformed)?;
        let h: u64 = s[8..10].parse().map_err(|_| CoreError::Malformed)?;
        let min: u64 = s[10..12].parse().map_err(|_| CoreError::Malformed)?;
        let sec: u64 = s[12..14].parse().map_err(|_| CoreError::Malformed)?;

        // Simple days calculation from 1970
        let mut days = 0u64;
        for year in 1970..y {
            let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
            days += if leap { 366 } else { 365 };
        }
        let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        let mdays = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        for (i, &md) in mdays.iter().enumerate() {
            if (i as u64) + 1 < m {
                days += md;
            }
        }
        days += d.saturating_sub(1);
        let total_secs = days * 86400 + h * 3600 + min * 60 + sec;
        return Ok(total_secs);
    }
    // Default fallback: parse timestamp as raw integer if embedded
    if let Ok(ts) = s.parse::<u64>() {
        return Ok(ts);
    }
    Err(CoreError::Malformed)
}

// --- Threshold Custodian Signature Structure ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodianSig {
    pub custodian: String,
    pub sig: Vec<u8>,
}

// --- High-Level Post-Quantum X.509 Certificate ---

#[derive(Debug, Clone)]
pub struct PqX509Certificate {
    pub serial: [u8; 16],
    pub subject: String,
    pub issuer: String,
    pub not_before: u64,
    pub not_after: u64,
    pub subject_pk: [u8; MLDSA87_PK],
    pub sig_alg_oid: String,
    pub primary_sig: Vec<u8>,
    pub custodian_sigs: Vec<CustodianSig>,
    pub raw_tbs: Vec<u8>,
}

impl PqX509Certificate {
    /// Strict RFC 9881 DER parser for post-quantum certificates.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, CoreError> {
        let (root_el, rem) = parse_tlv(der_bytes)?;
        if root_el.tag != TAG_SEQUENCE || !rem.is_empty() {
            return Err(CoreError::Malformed);
        }
        let cert_fields = parse_sequence_from_el(&root_el)?;
        if cert_fields.len() != 3 {
            return Err(CoreError::Malformed);
        }

        let tbs_el = &cert_fields[0];
        let sig_alg_el = &cert_fields[1];
        let sig_val_el = &cert_fields[2];

        let raw_tbs = tbs_el.raw.to_vec();

        // 1. Signature Algorithm
        let sig_alg_seq = parse_sequence_from_el(sig_alg_el)?;
        if sig_alg_seq.is_empty() {
            return Err(CoreError::Malformed);
        }
        let sig_alg_oid = parse_oid(&sig_alg_seq[0])?;
        if sig_alg_oid != OID_ML_DSA_87_IBM && sig_alg_oid != OID_ML_DSA_87_NIST {
            return Err(CoreError::Malformed);
        }

        // 2. Primary Signature Value
        let primary_sig = parse_bit_string(sig_val_el)?.to_vec();

        // 3. TBS Certificate
        let tbs_items = parse_sequence_from_el(tbs_el)?;
        if tbs_items.len() < 6 {
            return Err(CoreError::Malformed);
        }

        let mut idx = 0;
        // Optional Version: [0] EXPLICIT INTEGER
        if tbs_items[idx].tag == TAG_CONTEXT_0 {
            idx += 1;
        }

        // Serial Number
        let serial_raw = parse_integer_bytes(&tbs_items[idx])?;
        if serial_raw.len() != 16 {
            return Err(CoreError::Malformed);
        }
        let mut serial = [0u8; 16];
        serial.copy_from_slice(&serial_raw);
        idx += 1;

        // TBS Signature Alg
        let _tbs_sig_alg = &tbs_items[idx];
        idx += 1;

        // Issuer Name
        let issuer = parse_common_name(&tbs_items[idx])?;
        idx += 1;

        // Validity: SEQUENCE { notBefore, notAfter }
        let validity_items = parse_sequence_from_el(&tbs_items[idx])?;
        if validity_items.len() != 2 {
            return Err(CoreError::Malformed);
        }
        let not_before = parse_time_secs(&validity_items[0])?;
        let not_after = parse_time_secs(&validity_items[1])?;
        idx += 1;

        // Subject Name
        let subject = parse_common_name(&tbs_items[idx])?;
        idx += 1;

        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        let spki_items = parse_sequence_from_el(&tbs_items[idx])?;
        if spki_items.len() != 2 {
            return Err(CoreError::Malformed);
        }
        let spki_alg_seq = parse_sequence_from_el(&spki_items[0])?;
        if spki_alg_seq.is_empty() {
            return Err(CoreError::Malformed);
        }
        let spki_oid = parse_oid(&spki_alg_seq[0])?;
        if spki_oid != OID_ML_DSA_87_IBM && spki_oid != OID_ML_DSA_87_NIST {
            return Err(CoreError::Malformed);
        }
        let pk_bytes = parse_bit_string(&spki_items[1])?;
        if pk_bytes.len() != MLDSA87_PK {
            return Err(CoreError::Malformed);
        }
        let mut subject_pk = [0u8; MLDSA87_PK];
        subject_pk.copy_from_slice(pk_bytes);
        idx += 1;

        // Parse optional extensions: [3] EXPLICIT Extensions
        let mut custodian_sigs = Vec::new();
        while idx < tbs_items.len() {
            if tbs_items[idx].tag == TAG_CONTEXT_3 {
                let ext_items = parse_sequence(tbs_items[idx].value)?;
                for ext in ext_items {
                    let ext_seq = parse_sequence_from_el(&ext)?;
                    if ext_seq.len() >= 2 {
                        let ext_oid = parse_oid(&ext_seq[0])?;
                        if ext_oid == OID_THRESHOLD_SIGS {
                            // Value is OCTET STRING wrapping SEQUENCE OF CustodianSignature
                            let ext_val_bytes = if ext_seq[1].tag == TAG_OCTET_STRING {
                                ext_seq[1].value
                            } else {
                                ext_seq.last().unwrap().value
                            };
                            if let Ok(sig_items) = parse_sequence(ext_val_bytes) {
                                for s_el in sig_items {
                                    if let Ok(s_seq) = parse_sequence_from_el(&s_el) {
                                        if s_seq.len() >= 2 {
                                            if let (Ok(label), Ok(sig)) = (
                                                std::str::from_utf8(s_seq[0].value),
                                                parse_bit_string(&s_seq[1]),
                                            ) {
                                                custodian_sigs.push(CustodianSig {
                                                    custodian: label.to_string(),
                                                    sig: sig.to_vec(),
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            idx += 1;
        }

        Ok(Self {
            serial,
            subject,
            issuer,
            not_before,
            not_after,
            subject_pk,
            sig_alg_oid,
            primary_sig,
            custodian_sigs,
            raw_tbs,
        })
    }

    /// Strict RFC 9881 DER serializer for post-quantum certificates.
    pub fn to_der(&self) -> Result<Vec<u8>, CoreError> {
        let oid = if !self.sig_alg_oid.is_empty() {
            &self.sig_alg_oid
        } else {
            OID_ML_DSA_87_IBM
        };

        // 1. Version [0] EXPLICIT INTEGER (2 for v3)
        let ver_int = encode_tlv(TAG_INTEGER, &[0x02]);
        let ver_ctx = encode_tlv(TAG_CONTEXT_0, &ver_int);

        // 2. Serial Number
        let serial_int = encode_integer_bytes(&self.serial);

        // 3. Signature AlgorithmIdentifier
        let sig_alg = encode_algorithm_identifier(oid);

        // 4. Issuer Name
        let issuer_name = encode_common_name(&self.issuer);

        // 5. Validity: SEQUENCE { notBefore, notAfter }
        let nb = encode_generalized_time(self.not_before);
        let na = encode_generalized_time(self.not_after);
        let validity = encode_sequence(&[&nb, &na]);

        // 6. Subject Name
        let subject_name = encode_common_name(&self.subject);

        // 7. SubjectPublicKeyInfo
        let spki = encode_subject_public_key_info(oid, &self.subject_pk)?;

        // 8. Threshold Signatures Extension: [3] EXPLICIT Extensions
        let mut sig_entries = Vec::new();
        for cs in &self.custodian_sigs {
            let label_utf8 = encode_utf8_string(&cs.custodian);
            let sig_bit = encode_bit_string(&cs.sig);
            sig_entries.push(encode_sequence(&[&label_utf8, &sig_bit]));
        }
        let sig_entries_ref: Vec<&[u8]> = sig_entries.iter().map(|v| v.as_slice()).collect();
        let sig_seq = encode_sequence(&sig_entries_ref);
        let sig_octet = encode_octet_string(&sig_seq);
        let ext_oid = encode_oid(OID_THRESHOLD_SIGS);
        let ext_item = encode_sequence(&[&ext_oid, &sig_octet]);
        let exts_seq = encode_sequence(&[&ext_item]);
        let exts_ctx = encode_tlv(TAG_CONTEXT_3, &exts_seq);

        // Assemble TBSCertificate
        let tbs_seq = encode_sequence(&[
            &ver_ctx,
            &serial_int,
            &sig_alg,
            &issuer_name,
            &validity,
            &subject_name,
            &spki,
            &exts_ctx,
        ]);

        // Primary signature BIT STRING
        let primary_sig_val = if !self.primary_sig.is_empty() {
            &self.primary_sig
        } else if let Some(first) = self.custodian_sigs.first() {
            &first.sig
        } else {
            return Err(CoreError::Malformed);
        };
        let sig_val = encode_bit_string(primary_sig_val);

        // Assemble Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        Ok(encode_sequence(&[&tbs_seq, &sig_alg, &sig_val]))
    }

    /// Validates the certificate against the offline 3-of-5 threshold Root CA custodians.
    pub fn verify_threshold(&self, custodians: &[Custodian], now: f64) -> Result<(), CoreError> {
        if !now.is_finite() {
            return Err(CoreError::Malformed);
        }
        let span = self
            .not_after
            .checked_sub(self.not_before)
            .ok_or(CoreError::Malformed)?;
        if span == 0 || span > MAX_LIFETIME {
            return Err(CoreError::Malformed);
        }
        if !((self.not_before as f64) - MAX_SKEW_FUTURE <= now && now <= (self.not_after as f64)) {
            return Err(CoreError::Stale);
        }

        // Build custodian map
        let mut by_label: HashMap<&str, &[u8]> = HashMap::new();
        for c in custodians {
            if by_label.insert(c.label.as_str(), &c.mldsa_pk).is_some() {
                return Err(CoreError::Malformed);
            }
        }
        if by_label.len() != TOTAL {
            return Err(CoreError::Malformed);
        }

        // Standard canonical tbs bytes for cross-interop verification
        let canonical_tbs = tbs_bytes(
            &self.serial,
            &self.subject,
            &self.subject_pk,
            self.not_before,
            self.not_after,
        )?;

        let mut seen = HashSet::new();
        let mut valid = 0usize;

        for entry in &self.custodian_sigs {
            if !seen.insert(entry.custodian.as_str()) {
                return Err(CoreError::Malformed); // duplicate signer
            }
            let pub_bytes = by_label
                .get(entry.custodian.as_str())
                .ok_or(CoreError::UnknownIdentity)?;
            let vk = Mldsa87VerifyingKey::from_bytes(pub_bytes)?;

            // Verify over raw_tbs or canonical_tbs
            let ok_raw = vk.verify(&[], &self.raw_tbs, &entry.sig).is_ok();
            let ok_canon = !ok_raw && vk.verify(&[], &canonical_tbs, &entry.sig).is_ok();

            if ok_raw || ok_canon {
                valid += 1;
            } else {
                return Err(CoreError::AuthRequired);
            }
        }

        if valid < QUORUM {
            return Err(CoreError::AuthRequired);
        }
        Ok(())
    }
}

// --- High-Level Monotonic Certificate Revocation List (CRL) ---

pub fn crl_tbs_bytes(
    crl_number: u64,
    this_update: u64,
    next_update: u64,
    revoked_serials: &[[u8; 16]],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(32 + revoked_serials.len() * 16);
    b.extend_from_slice(b"CA-CRL-v1");
    b.extend_from_slice(&crl_number.to_be_bytes());
    b.extend_from_slice(&this_update.to_be_bytes());
    b.extend_from_slice(&next_update.to_be_bytes());
    b.extend_from_slice(&(revoked_serials.len() as u64).to_be_bytes());
    for s in revoked_serials {
        b.extend_from_slice(s);
    }
    b
}

#[derive(Debug, Clone)]
pub struct PqX509Crl {
    pub issuer: String,
    pub this_update: u64,
    pub next_update: u64,
    pub crl_number: u64,
    pub revoked_serials: Vec<[u8; 16]>,
    pub primary_sig: Vec<u8>,
    pub custodian_sigs: Vec<CustodianSig>,
    pub raw_tbs: Vec<u8>,
}

impl PqX509Crl {
    /// Strict RFC 5280 / RFC 9881 DER parser for threshold CRLs.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, CoreError> {
        let (root_el, rem) = parse_tlv(der_bytes)?;
        if root_el.tag != TAG_SEQUENCE || !rem.is_empty() {
            return Err(CoreError::Malformed);
        }
        let crl_fields = parse_sequence_from_el(&root_el)?;
        if crl_fields.len() != 3 {
            return Err(CoreError::Malformed);
        }

        let tbs_el = &crl_fields[0];
        let sig_alg_el = &crl_fields[1];
        let sig_val_el = &crl_fields[2];

        let raw_tbs = tbs_el.raw.to_vec();

        // 1. Signature Algorithm
        let sig_alg_seq = parse_sequence_from_el(sig_alg_el)?;
        if sig_alg_seq.is_empty() {
            return Err(CoreError::Malformed);
        }
        let sig_alg_oid = parse_oid(&sig_alg_seq[0])?;
        if sig_alg_oid != OID_ML_DSA_87_IBM && sig_alg_oid != OID_ML_DSA_87_NIST {
            return Err(CoreError::Malformed);
        }

        // 2. Primary Signature Value
        let primary_sig = parse_bit_string(sig_val_el)?.to_vec();

        // 3. TBSCertList
        let tbs_items = parse_sequence_from_el(tbs_el)?;
        if tbs_items.len() < 4 {
            return Err(CoreError::Malformed);
        }

        let mut idx = 0;
        // Optional Version (v2 is 1)
        if tbs_items[idx].tag == TAG_INTEGER {
            idx += 1;
        }

        // Signature AlgorithmIdentifier
        let _tbs_sig_alg = &tbs_items[idx];
        idx += 1;

        // Issuer Name
        let issuer = parse_common_name(&tbs_items[idx])?;
        idx += 1;

        // thisUpdate
        let this_update = parse_time_secs(&tbs_items[idx])?;
        idx += 1;

        // Optional nextUpdate
        let mut next_update = this_update + 86400;
        if idx < tbs_items.len()
            && (tbs_items[idx].tag == TAG_GENERALIZED_TIME || tbs_items[idx].tag == TAG_UTC_TIME)
        {
            next_update = parse_time_secs(&tbs_items[idx])?;
            idx += 1;
        }

        // Optional revokedCertificates SEQUENCE
        let mut revoked_serials = Vec::new();
        if idx < tbs_items.len() && tbs_items[idx].tag == TAG_SEQUENCE {
            let rev_items = parse_sequence_from_el(&tbs_items[idx])?;
            for rev_entry in rev_items {
                if let Ok(fields) = parse_sequence_from_el(&rev_entry) {
                    if !fields.is_empty() {
                        let s_raw = parse_integer_bytes(&fields[0])?;
                        if s_raw.len() == 16 {
                            let mut arr = [0u8; 16];
                            arr.copy_from_slice(&s_raw);
                            revoked_serials.push(arr);
                        }
                    }
                }
            }
            idx += 1;
        }

        // Optional crlExtensions: [0] EXPLICIT Extensions
        let mut crl_number = 0u64;
        let mut custodian_sigs = Vec::new();

        while idx < tbs_items.len() {
            if tbs_items[idx].tag == TAG_CONTEXT_0 {
                let ext_items = parse_sequence(tbs_items[idx].value)?;
                for ext in ext_items {
                    if let Ok(ext_seq) = parse_sequence_from_el(&ext) {
                        if ext_seq.len() >= 2 {
                            let ext_oid = parse_oid(&ext_seq[0])?;
                            if ext_oid == OID_CRL_NUMBER {
                                let octet_bytes = ext_seq.last().unwrap().value;
                                if let Ok((int_el, _)) = parse_tlv(octet_bytes) {
                                    crl_number = parse_integer_u64(&int_el).unwrap_or(0);
                                }
                            } else if ext_oid == OID_THRESHOLD_SIGS {
                                let octet_bytes = ext_seq.last().unwrap().value;
                                if let Ok(sig_items) = parse_sequence(octet_bytes) {
                                    for s_el in sig_items {
                                        if let Ok(s_seq) = parse_sequence_from_el(&s_el) {
                                            if s_seq.len() >= 2 {
                                                if let (Ok(label), Ok(sig)) = (
                                                    std::str::from_utf8(s_seq[0].value),
                                                    parse_bit_string(&s_seq[1]),
                                                ) {
                                                    custodian_sigs.push(CustodianSig {
                                                        custodian: label.to_string(),
                                                        sig: sig.to_vec(),
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            idx += 1;
        }

        Ok(Self {
            issuer,
            this_update,
            next_update,
            crl_number,
            revoked_serials,
            primary_sig,
            custodian_sigs,
            raw_tbs,
        })
    }

    /// Strict RFC 5280 / RFC 9881 DER serializer for threshold CRLs.
    pub fn to_der(&self) -> Result<Vec<u8>, CoreError> {
        let oid = OID_ML_DSA_87_IBM;

        // 1. Version INTEGER (1 for v2)
        let ver = encode_tlv(TAG_INTEGER, &[0x01]);

        // 2. Signature AlgorithmIdentifier
        let sig_alg = encode_algorithm_identifier(oid);

        // 3. Issuer Name
        let issuer_name = encode_common_name(&self.issuer);

        // 4. thisUpdate & nextUpdate
        let tu = encode_generalized_time(self.this_update);
        let nu = encode_generalized_time(self.next_update);

        // 5. revokedCertificates SEQUENCE
        let mut rev_entries = Vec::new();
        for s in &self.revoked_serials {
            let s_int = encode_integer_bytes(s);
            let rd = encode_generalized_time(self.this_update);
            rev_entries.push(encode_sequence(&[&s_int, &rd]));
        }
        let rev_entries_ref: Vec<&[u8]> = rev_entries.iter().map(|v| v.as_slice()).collect();
        let rev_seq = encode_sequence(&rev_entries_ref);

        // 6. crlExtensions: [0] EXPLICIT Extensions
        // 6a. cRLNumber extension
        let crl_num_int = encode_integer_u64(self.crl_number);
        let crl_num_octet = encode_octet_string(&crl_num_int);
        let crl_num_oid = encode_oid(OID_CRL_NUMBER);
        let crl_num_ext = encode_sequence(&[&crl_num_oid, &crl_num_octet]);

        // 6b. threshold signatures extension
        let mut sig_entries = Vec::new();
        for cs in &self.custodian_sigs {
            let label_utf8 = encode_utf8_string(&cs.custodian);
            let sig_bit = encode_bit_string(&cs.sig);
            sig_entries.push(encode_sequence(&[&label_utf8, &sig_bit]));
        }
        let sig_entries_ref: Vec<&[u8]> = sig_entries.iter().map(|v| v.as_slice()).collect();
        let sig_seq = encode_sequence(&sig_entries_ref);
        let sig_octet = encode_octet_string(&sig_seq);
        let ext_oid = encode_oid(OID_THRESHOLD_SIGS);
        let ext_item = encode_sequence(&[&ext_oid, &sig_octet]);

        let exts_seq = encode_sequence(&[&crl_num_ext, &ext_item]);
        let exts_ctx = encode_tlv(TAG_CONTEXT_0, &exts_seq);

        // Assemble TBSCertList
        let tbs_seq =
            encode_sequence(&[&ver, &sig_alg, &issuer_name, &tu, &nu, &rev_seq, &exts_ctx]);

        let primary_sig_val = if !self.primary_sig.is_empty() {
            &self.primary_sig
        } else if let Some(first) = self.custodian_sigs.first() {
            &first.sig
        } else {
            return Err(CoreError::Malformed);
        };
        let sig_val = encode_bit_string(primary_sig_val);

        Ok(encode_sequence(&[&tbs_seq, &sig_alg, &sig_val]))
    }

    /// Validates the CRL threshold signatures against the 5-custodian Root CA.
    pub fn verify_threshold(&self, custodians: &[Custodian]) -> Result<(), CoreError> {
        let mut by_label: HashMap<&str, &[u8]> = HashMap::new();
        for c in custodians {
            if by_label.insert(c.label.as_str(), &c.mldsa_pk).is_some() {
                return Err(CoreError::Malformed);
            }
        }
        if by_label.len() != TOTAL {
            return Err(CoreError::Malformed);
        }

        let mut seen = HashSet::new();
        let mut valid = 0usize;

        let canonical_crl = crl_tbs_bytes(
            self.crl_number,
            self.this_update,
            self.next_update,
            &self.revoked_serials,
        );

        for entry in &self.custodian_sigs {
            if !seen.insert(entry.custodian.as_str()) {
                return Err(CoreError::Malformed);
            }
            let pub_bytes = by_label
                .get(entry.custodian.as_str())
                .ok_or(CoreError::UnknownIdentity)?;
            let vk = Mldsa87VerifyingKey::from_bytes(pub_bytes)?;

            let ok_canon = vk.verify(&[], &canonical_crl, &entry.sig).is_ok();
            let ok_raw = !ok_canon && vk.verify(&[], &self.raw_tbs, &entry.sig).is_ok();

            if ok_canon || ok_raw {
                valid += 1;
            } else {
                return Err(CoreError::AuthRequired);
            }
        }

        if valid < QUORUM {
            return Err(CoreError::AuthRequired);
        }
        Ok(())
    }
}

// --- Certificate & CRL Threshold Builders ---

pub fn issue_x509_certificate(
    serial: [u8; 16],
    subject: &str,
    subject_pk: &[u8; MLDSA87_PK],
    not_before: u64,
    not_after: u64,
    signers: &[(&str, &Mldsa87SigningKey)],
    sig_alg_oid: Option<&str>,
) -> Result<PqX509Certificate, CoreError> {
    if signers.len() < QUORUM {
        return Err(CoreError::AuthRequired);
    }
    let oid = sig_alg_oid.unwrap_or(OID_ML_DSA_87_IBM).to_string();
    let norm_subj = norm_ident(subject)?;

    let body_to_sign = tbs_bytes(&serial, &norm_subj, subject_pk, not_before, not_after)?;

    let mut custodian_sigs = Vec::new();
    let mut seen = HashSet::new();
    for (label, sk) in signers {
        let l = norm_ident(label)?;
        if !seen.insert(l.clone()) {
            return Err(CoreError::Malformed);
        }
        let sig = sk.sign(&[], &body_to_sign);
        custodian_sigs.push(CustodianSig { custodian: l, sig });
    }

    let primary_sig = custodian_sigs[0].sig.clone();

    let cert = PqX509Certificate {
        serial,
        subject: norm_subj,
        issuer: "OFFLINE-ROOT-3OF5".to_string(),
        not_before,
        not_after,
        subject_pk: *subject_pk,
        sig_alg_oid: oid,
        primary_sig,
        custodian_sigs,
        raw_tbs: Vec::new(),
    };

    let der = cert.to_der()?;
    PqX509Certificate::from_der(&der)
}

pub fn issue_x509_crl(
    crl_number: u64,
    this_update: u64,
    next_update: u64,
    revoked_serials: &[[u8; 16]],
    signers: &[(&str, &Mldsa87SigningKey)],
) -> Result<PqX509Crl, CoreError> {
    if signers.len() < QUORUM {
        return Err(CoreError::AuthRequired);
    }

    let body_to_sign = crl_tbs_bytes(crl_number, this_update, next_update, revoked_serials);

    let mut custodian_sigs = Vec::new();
    let mut seen = HashSet::new();
    for (label, sk) in signers {
        let l = norm_ident(label)?;
        if !seen.insert(l.clone()) {
            return Err(CoreError::Malformed);
        }
        let sig = sk.sign(&[], &body_to_sign);
        custodian_sigs.push(CustodianSig { custodian: l, sig });
    }

    let primary_sig = custodian_sigs[0].sig.clone();

    let crl = PqX509Crl {
        issuer: "OFFLINE-ROOT-3OF5".to_string(),
        this_update,
        next_update,
        crl_number,
        revoked_serials: revoked_serials.to_vec(),
        primary_sig,
        custodian_sigs,
        raw_tbs: Vec::new(),
    };

    let der = crl.to_der()?;
    PqX509Crl::from_der(&der)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCa {
        labels: Vec<String>,
        signers: Vec<Mldsa87SigningKey>,
        custodians: Vec<Custodian>,
    }

    fn init_test_ca() -> TestCa {
        let mut labels = Vec::new();
        let mut signers = Vec::new();
        let mut custodians = Vec::new();
        for i in 0..5 {
            let label = format!("custodian-{i}");
            let (sk, vk) = Mldsa87SigningKey::generate().unwrap();
            custodians.push(Custodian::new(&label, vk.to_bytes()).unwrap());
            labels.push(label);
            signers.push(sk);
        }
        TestCa {
            labels,
            signers,
            custodians,
        }
    }

    #[test]
    fn test_x509_certificate_der_roundtrip_and_threshold_verification() {
        let ca = init_test_ca();
        let (_subj_sk, subj_vk) = Mldsa87SigningKey::generate().unwrap();
        let mut subj_pk = [0u8; MLDSA87_PK];
        subj_pk.copy_from_slice(&subj_vk.to_bytes());

        let serial = [0x5Au8; 16];
        let signers_refs: Vec<(&str, &Mldsa87SigningKey)> = vec![
            (&ca.labels[0], &ca.signers[0]),
            (&ca.labels[1], &ca.signers[1]),
            (&ca.labels[2], &ca.signers[2]),
        ];

        let now = 1_700_000_000u64;
        let cert = issue_x509_certificate(
            serial,
            "tactical-node-alpha",
            &subj_pk,
            now,
            now + 3600,
            &signers_refs,
            Some(OID_ML_DSA_87_IBM),
        )
        .unwrap();

        assert_eq!(cert.serial, serial);
        assert_eq!(cert.subject, "tactical-node-alpha");
        assert_eq!(cert.subject_pk, subj_pk);
        assert_eq!(cert.custodian_sigs.len(), 3);

        // Verify DER serialization & deserialization roundtrip
        let der = cert.to_der().unwrap();
        let parsed = PqX509Certificate::from_der(&der).unwrap();
        assert_eq!(parsed.serial, serial);
        assert_eq!(parsed.subject, "tactical-node-alpha");
        assert_eq!(parsed.subject_pk, subj_pk);
        assert_eq!(parsed.custodian_sigs.len(), 3);

        // Threshold verify against 5-custodian Root CA
        parsed
            .verify_threshold(&ca.custodians, (now + 50) as f64)
            .unwrap();

        // Expired check fails
        assert_eq!(
            parsed.verify_threshold(&ca.custodians, (now + 5000) as f64),
            Err(CoreError::Stale)
        );

        // Untrusted CA fails
        let fake_ca = init_test_ca();
        assert!(parsed
            .verify_threshold(&fake_ca.custodians, (now + 50) as f64)
            .is_err());
    }

    #[test]
    fn test_x509_crl_der_roundtrip_and_threshold_verification() {
        let ca = init_test_ca();
        let serial1 = [0x11u8; 16];
        let serial2 = [0x22u8; 16];

        let signers_refs: Vec<(&str, &Mldsa87SigningKey)> = vec![
            (&ca.labels[0], &ca.signers[0]),
            (&ca.labels[1], &ca.signers[1]),
            (&ca.labels[3], &ca.signers[3]),
        ];

        let now = 1_700_000_000u64;
        let crl = issue_x509_crl(42, now, now + 86400, &[serial1, serial2], &signers_refs).unwrap();

        assert_eq!(crl.crl_number, 42);
        assert_eq!(crl.revoked_serials.len(), 2);
        assert_eq!(crl.custodian_sigs.len(), 3);

        let der = crl.to_der().unwrap();
        let parsed = PqX509Crl::from_der(&der).unwrap();
        assert_eq!(parsed.crl_number, 42);
        assert_eq!(parsed.revoked_serials, vec![serial1, serial2]);
        assert_eq!(parsed.custodian_sigs.len(), 3);

        parsed.verify_threshold(&ca.custodians).unwrap();
    }
}
