//! Chaff frame typing. Chaff is authenticated like any frame, absorbed on
//! receipt, and never surfaces to the application or logs above debug.

/// Wire type byte for chaff (heartbeat replacement).
pub const CHAFF_TYPE: u8 = 0xFF;
