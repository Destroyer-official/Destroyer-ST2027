// Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
// NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
//! Padding budgets (re-exported from frame quanta) and chaff policy.
//!
//! - Outbound payloads are padded to 256 / 512 / 1232 bytes.
//! - Chaff frames (type 0xFF) replace the fixed 30s plaintext heartbeat:
//!   sent at uniform-random 2.5–6.0s intervals so idle rhythm is flat.

/// Chaff interval bounds, seconds.
pub const CHAFF_MIN_SECS: f64 = 2.5;
/// Chaff interval bounds, seconds.
pub const CHAFF_MAX_SECS: f64 = 6.0;

pub use crate::frame::FRAME_QUANTA;
