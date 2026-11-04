//! MMHS (Military Message Handling System) Telegram Formatting & Parsing.
//!
//! Implements STANAG 4406 / ACP 127-style precedence-coded telegram
//! envelopes used by the destroyer data-plane.  Every outbound telegram
//! passes through the NSA RTB dirty-word scanner (`inspect_content_rtb`)
//! before formatting; messages below `TopSecret` clearance that contain
//! classified indicators are fail-closed rejected.
//!
//! ## Wire format
//!
//! ```text
//! [MMHS PRECEDENCE=<label> // <clearance> // <caveats>] <body>
//! ```

use crate::policy::CoreError;
use crate::zero_trust::{
    inspect_content_rtb, ClearanceLevel, CAVEAT_EYES_ONLY, CAVEAT_NOFORN, CAVEAT_REL_TO_COALITION,
    CAVEAT_SI_TK_G,
};
use core::fmt;

// ---------------------------------------------------------------------------
// Precedence
// ---------------------------------------------------------------------------

/// ACP 127 / STANAG 4406 message precedence codes.
///
/// Each variant carries a single-character code letter and a numeric rank
/// (1 = highest urgency).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precedence {
    /// Y — FLASH OVERRIDE (rank 1)
    FlashOverride,
    /// Z — FLASH (rank 2)
    Flash,
    /// O — IMMEDIATE (rank 3)
    Immediate,
    /// P — PRIORITY (rank 4)
    Priority,
    /// R — ROUTINE (rank 5)
    Routine,
}

impl Precedence {
    /// Single-character ACP 127 code letter.
    pub fn code_letter(self) -> char {
        match self {
            Precedence::FlashOverride => 'Y',
            Precedence::Flash => 'Z',
            Precedence::Immediate => 'O',
            Precedence::Priority => 'P',
            Precedence::Routine => 'R',
        }
    }

    /// Numeric rank (1 = highest urgency, 5 = lowest).
    pub fn rank(self) -> u8 {
        match self {
            Precedence::FlashOverride => 1,
            Precedence::Flash => 2,
            Precedence::Immediate => 3,
            Precedence::Priority => 4,
            Precedence::Routine => 5,
        }
    }

    /// Human-readable label used in the wire envelope.
    pub fn label(self) -> &'static str {
        match self {
            Precedence::FlashOverride => "FLASH_OVERRIDE",
            Precedence::Flash => "FLASH",
            Precedence::Immediate => "IMMEDIATE",
            Precedence::Priority => "PRIORITY",
            Precedence::Routine => "ROUTINE",
        }
    }

    /// Parse from a single ACP 127 code letter.
    pub fn from_code(letter: char) -> Result<Self, CoreError> {
        match letter.to_ascii_uppercase() {
            'Y' => Ok(Precedence::FlashOverride),
            'Z' => Ok(Precedence::Flash),
            'O' => Ok(Precedence::Immediate),
            'P' => Ok(Precedence::Priority),
            'R' => Ok(Precedence::Routine),
            _ => Err(CoreError::Malformed),
        }
    }

    /// Parse from a human-readable label (case-insensitive).
    pub fn from_label(label: &str) -> Result<Self, CoreError> {
        let upper = label.trim().to_ascii_uppercase();
        match upper.as_str() {
            "FLASH_OVERRIDE" => Ok(Precedence::FlashOverride),
            "FLASH" => Ok(Precedence::Flash),
            "IMMEDIATE" => Ok(Precedence::Immediate),
            "PRIORITY" => Ok(Precedence::Priority),
            "ROUTINE" => Ok(Precedence::Routine),
            _ => Err(CoreError::Malformed),
        }
    }
}

impl fmt::Display for Precedence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Caveats helpers
// ---------------------------------------------------------------------------

/// Known caveat bits in display order.
const CAVEAT_TABLE: [(u32, &str); 4] = [
    (CAVEAT_NOFORN, "NOFORN"),
    (CAVEAT_REL_TO_COALITION, "REL_TO_COALITION"),
    (CAVEAT_EYES_ONLY, "EYES_ONLY"),
    (CAVEAT_SI_TK_G, "SI_TK_G"),
];

/// Render a caveat bitmask as a comma-separated human-readable string.
///
/// Unknown bits are silently ignored.
///
/// # Examples
///
/// ```
/// # use destroyer_core::mmhs::format_caveats;
/// # use destroyer_core::zero_trust::{CAVEAT_NOFORN, CAVEAT_EYES_ONLY};
/// assert_eq!(format_caveats(CAVEAT_NOFORN | CAVEAT_EYES_ONLY), "NOFORN,EYES_ONLY");
/// ```
pub fn format_caveats(caveats: u32) -> String {
    let mut parts = Vec::new();
    for &(bit, name) in &CAVEAT_TABLE {
        if caveats & bit != 0 {
            parts.push(name);
        }
    }
    parts.join(",")
}

/// Parse a comma-separated caveat string back into a bitmask.
///
/// Unknown tokens are rejected with `CoreError::Malformed`.
fn parse_caveats(s: &str) -> Result<u32, CoreError> {
    if s.is_empty() {
        return Ok(0);
    }
    let mut mask = 0u32;
    for token in s.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        let bit = match t {
            "NOFORN" => CAVEAT_NOFORN,
            "REL_TO_COALITION" => CAVEAT_REL_TO_COALITION,
            "EYES_ONLY" => CAVEAT_EYES_ONLY,
            "SI_TK_G" => CAVEAT_SI_TK_G,
            _ => return Err(CoreError::Malformed),
        };
        mask |= bit;
    }
    Ok(mask)
}

/// Parse a clearance label back to a [`ClearanceLevel`].
fn clearance_from_label(label: &str) -> Result<ClearanceLevel, CoreError> {
    match label.trim() {
        "UNCLASSIFIED" => Ok(ClearanceLevel::Unclassified),
        "CONFIDENTIAL" => Ok(ClearanceLevel::Confidential),
        "SECRET" => Ok(ClearanceLevel::Secret),
        "TOP_SECRET" => Ok(ClearanceLevel::TopSecret),
        _ => Err(CoreError::Malformed),
    }
}

// ---------------------------------------------------------------------------
// Telegram formatting
// ---------------------------------------------------------------------------

/// Envelope prefix / suffix tokens.
const ENVELOPE_OPEN: &[u8] = b"[MMHS PRECEDENCE=";
const ENVELOPE_SEP: &[u8] = b" // ";
const ENVELOPE_CLOSE: &[u8] = b"] ";

/// Format a MMHS telegram envelope around `message`.
///
/// The outbound body is scanned by the NSA RTB dirty-word filter
/// (`inspect_content_rtb`).  If the scan detects a classified indicator
/// **and** `clearance` is below `TopSecret`, the function fails with
/// [`CoreError::ZeroTrustViolation`] to prevent spillage.
///
/// # Wire format
///
/// ```text
/// [MMHS PRECEDENCE=FLASH_OVERRIDE // TOP_SECRET // NOFORN] <body bytes>
/// ```
pub fn format_telegram(
    precedence: Precedence,
    clearance: ClearanceLevel,
    caveats: u32,
    message: &[u8],
) -> Result<Vec<u8>, CoreError> {
    // ── RTB spillage scan ────────────────────────────────────────────
    if let Err(_indicator) = inspect_content_rtb(message) {
        if clearance != ClearanceLevel::TopSecret {
            return Err(CoreError::ZeroTrustViolation);
        }
        // TopSecret clearance: dirty words are expected / permitted.
    }

    // ── Build envelope ───────────────────────────────────────────────
    let caveats_str = format_caveats(caveats);
    let clearance_str = clearance.as_str();
    let label = precedence.label();

    let mut out = Vec::with_capacity(
        ENVELOPE_OPEN.len()
            + label.len()
            + ENVELOPE_SEP.len()
            + clearance_str.len()
            + ENVELOPE_SEP.len()
            + caveats_str.len()
            + ENVELOPE_CLOSE.len()
            + message.len(),
    );

    out.extend_from_slice(ENVELOPE_OPEN);
    out.extend_from_slice(label.as_bytes());
    out.extend_from_slice(ENVELOPE_SEP);
    out.extend_from_slice(clearance_str.as_bytes());
    out.extend_from_slice(ENVELOPE_SEP);
    out.extend_from_slice(caveats_str.as_bytes());
    out.extend_from_slice(ENVELOPE_CLOSE);
    out.extend_from_slice(message);

    Ok(out)
}

// ---------------------------------------------------------------------------
// Telegram parsing
// ---------------------------------------------------------------------------

/// Parse a MMHS telegram envelope, returning `(precedence, clearance, caveats, body)`.
///
/// Returns [`CoreError::Malformed`] when the envelope does not match the
/// expected `[MMHS PRECEDENCE=… // … // …] <body>` structure.
pub fn parse_telegram(
    telegram: &[u8],
) -> Result<(Precedence, ClearanceLevel, u32, Vec<u8>), CoreError> {
    // Convert to UTF-8 — the envelope is always ASCII.
    let text = core::str::from_utf8(telegram).map_err(|_| CoreError::Malformed)?;

    // Locate envelope brackets.
    let open_end = text.find(']').ok_or(CoreError::Malformed)?;
    if !text.starts_with("[MMHS PRECEDENCE=") {
        return Err(CoreError::Malformed);
    }

    let inner = &text["[MMHS PRECEDENCE=".len()..open_end];

    // Split on " // " — expect exactly 3 fields.
    let parts: Vec<&str> = inner.split(" // ").collect();
    if parts.len() != 3 {
        return Err(CoreError::Malformed);
    }

    let precedence = Precedence::from_label(parts[0])?;
    let clearance = clearance_from_label(parts[1])?;
    let caveats = parse_caveats(parts[2])?;

    // Body starts after "] " (bracket + space).
    let body_start = open_end + 2; // ']' + ' '
    if body_start > telegram.len() {
        return Err(CoreError::Malformed);
    }
    let body = telegram[body_start..].to_vec();

    Ok((precedence, clearance, caveats, body))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zero_trust::{CAVEAT_EYES_ONLY, CAVEAT_NOFORN, CAVEAT_REL_TO_COALITION, CAVEAT_SI_TK_G};

    #[test]
    fn format_parse_roundtrip() {
        let msg = b"BRAVO ZULU ALL STATIONS REPORT";
        let prec = Precedence::FlashOverride;
        let clr = ClearanceLevel::Secret;
        let cavs = CAVEAT_NOFORN | CAVEAT_EYES_ONLY;

        let telegram = format_telegram(prec, clr, cavs, msg).expect("format failed");
        let (p2, c2, cv2, body) = parse_telegram(&telegram).expect("parse failed");

        assert_eq!(p2, prec);
        assert_eq!(c2, clr);
        assert_eq!(cv2, cavs);
        assert_eq!(body, msg);
    }

    #[test]
    fn rtb_blocks_below_top_secret() {
        // "top secret" is a dirty word; SECRET clearance must be rejected.
        let msg = b"Relay top secret coordinates to HQ";
        let result = format_telegram(
            Precedence::Flash,
            ClearanceLevel::Secret,
            CAVEAT_NOFORN,
            msg,
        );
        assert_eq!(result, Err(CoreError::ZeroTrustViolation));
    }

    #[test]
    fn rtb_allows_top_secret_clearance() {
        // TopSecret clearance permits dirty words in the body.
        let msg = b"Relay top secret coordinates to HQ";
        let result = format_telegram(
            Precedence::Immediate,
            ClearanceLevel::TopSecret,
            CAVEAT_NOFORN | CAVEAT_SI_TK_G,
            msg,
        );
        assert!(result.is_ok(), "TopSecret clearance must permit RTB words");
    }

    #[test]
    fn malformed_parse_fails() {
        assert_eq!(parse_telegram(b"garbage"), Err(CoreError::Malformed));
        assert_eq!(parse_telegram(b"[MMHS bad]"), Err(CoreError::Malformed));
        assert_eq!(parse_telegram(b""), Err(CoreError::Malformed));
    }

    #[test]
    fn all_precedences_format() {
        let cases = [
            ('Y', "FLASH_OVERRIDE", Precedence::FlashOverride, 1u8),
            ('Z', "FLASH", Precedence::Flash, 2),
            ('O', "IMMEDIATE", Precedence::Immediate, 3),
            ('P', "PRIORITY", Precedence::Priority, 4),
            ('R', "ROUTINE", Precedence::Routine, 5),
        ];
        for (code, label, variant, rank) in &cases {
            assert_eq!(Precedence::from_code(*code).unwrap(), *variant);
            assert_eq!(Precedence::from_label(label).unwrap(), *variant);
            assert_eq!(variant.code_letter(), *code);
            assert_eq!(variant.label(), *label);
            assert_eq!(variant.rank(), *rank);
            assert_eq!(format!("{variant}"), *label);
        }
    }

    #[test]
    fn caveats_roundtrip() {
        let combos: &[(u32, &str)] = &[
            (0, ""),
            (CAVEAT_NOFORN, "NOFORN"),
            (CAVEAT_REL_TO_COALITION, "REL_TO_COALITION"),
            (CAVEAT_EYES_ONLY, "EYES_ONLY"),
            (CAVEAT_SI_TK_G, "SI_TK_G"),
            (CAVEAT_NOFORN | CAVEAT_EYES_ONLY, "NOFORN,EYES_ONLY"),
            (
                CAVEAT_NOFORN | CAVEAT_REL_TO_COALITION | CAVEAT_EYES_ONLY | CAVEAT_SI_TK_G,
                "NOFORN,REL_TO_COALITION,EYES_ONLY,SI_TK_G",
            ),
        ];
        for &(mask, expected) in combos {
            let formatted = format_caveats(mask);
            assert_eq!(formatted, expected, "format_caveats({mask:#x})");
            let parsed = parse_caveats(&formatted).expect("parse_caveats failed");
            assert_eq!(parsed, mask, "parse_caveats round-trip for {mask:#x}");
        }
    }
}
