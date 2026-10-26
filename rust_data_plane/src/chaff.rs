// Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
// NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
//! Chaff frame typing. Chaff is authenticated like any frame, absorbed on
//! receipt, and never surfaces to the application or logs above debug.

/// Wire type byte for chaff (heartbeat replacement).
pub const CHAFF_TYPE: u8 = 0xFF;
