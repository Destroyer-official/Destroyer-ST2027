//! Push-To-Talk (PTT) Tactical Voice Burst Envelope.
//!
//! Provides quantized voice-burst metadata encapsulation and audio frame packaging
//! for low-latency tactical tactical radio transmission across zero-gap multi-layer channels.

use crate::policy::CoreError;

/// Push-To-Talk voice burst envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PttVoiceBurst {
    pub callsign: String,
    pub frame_count: u32,
    pub duration_ms: u32,
    pub audio_payload: Vec<u8>,
}

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

/// Package audio bytes into a tactical voice burst wire envelope:
/// `PTT:<frames>:<duration_ms>:<callsign>:<b64_audio>`
pub fn package_ptt_burst(
    callsign: &str,
    frame_count: u32,
    duration_ms: u32,
    audio_payload: &[u8],
) -> Vec<u8> {
    let b64 = base64_encode(audio_payload);
    format!("PTT:{}:{}:{}:{}", frame_count, duration_ms, callsign, b64).into_bytes()
}

/// Unpack an incoming PTT wire burst envelope.
pub fn unpack_ptt_burst(payload: &[u8]) -> Result<PttVoiceBurst, CoreError> {
    let s = core::str::from_utf8(payload).map_err(|_| CoreError::Malformed)?;
    if !s.starts_with("PTT:") {
        return Err(CoreError::Malformed);
    }

    let parts: Vec<&str> = s.splitn(5, ':').collect();
    if parts.len() < 5 {
        return Err(CoreError::Malformed);
    }

    let frame_count: u32 = parts[1].parse().map_err(|_| CoreError::Malformed)?;
    let duration_ms: u32 = parts[2].parse().map_err(|_| CoreError::Malformed)?;
    let callsign = parts[3].to_string();
    let audio_payload = base64_decode(parts[4]).map_err(|_| CoreError::Malformed)?;

    Ok(PttVoiceBurst {
        callsign,
        frame_count,
        duration_ms,
        audio_payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptt_burst_roundtrip() {
        let raw_audio = vec![0x33u8; 480]; // e.g. 20ms of audio frame
        let wire = package_ptt_burst("VIPER_LEADER", 10, 200, &raw_audio);

        let burst = unpack_ptt_burst(&wire).expect("unpack");
        assert_eq!(burst.callsign, "VIPER_LEADER");
        assert_eq!(burst.frame_count, 10);
        assert_eq!(burst.duration_ms, 200);
        assert_eq!(burst.audio_payload, raw_audio);
    }

    #[test]
    fn malformed_ptt_fails() {
        assert_eq!(unpack_ptt_burst(b"INVALID_HEADER"), Err(CoreError::Malformed));
        assert_eq!(unpack_ptt_burst(b"PTT:not_num:200:CALL:data"), Err(CoreError::Malformed));
    }
}

