//! Integration test verifying MTU framing budget and quantum invariants against compiled constants.
//!
//! Enforces:
//! - RFC 8200 IPv6 minimum MTU (1280 octets) constraint.
//! - UDP header overhead (8 octets).
//! - IPv6 base header overhead (40 octets).
//! - Wire frame overhead (27 octets: 8 seq + 2 len + 1 type + 16 tag).
//! - Maximum payload capacity of exactly 1205 octets at default wire quantum (1232 octets).

use destroyer_core::aead::{FrameKey, DIR_SEND};
use destroyer_core::frame::{FRAME_OVERHEAD, FRAME_QUANTA, MAX_PAYLOAD};
use destroyer_core::pacing::{build_data_frame_directed, DEFAULT_WIRE_QUANTUM};

#[test]
fn test_compiled_mtu_constants_and_rfc8200_budget() {
    assert_eq!(FRAME_OVERHEAD, 27, "Wire overhead must be exactly 27 octets (8 seq + 2 len + 1 type + 16 tag)");
    assert_eq!(DEFAULT_WIRE_QUANTUM, 1232, "Default wire quantum must be exactly 1232 octets");
    assert_eq!(MAX_PAYLOAD, 1205, "Maximum payload capacity must be exactly 1205 octets (1232 - 27)");

    const IPV6_HEADER_LEN: usize = 40;
    const UDP_HEADER_LEN: usize = 8;
    const IPV6_MIN_MTU: usize = 1280;

    // Exact RFC 8200 budget balance
    assert_eq!(
        MAX_PAYLOAD + FRAME_OVERHEAD + UDP_HEADER_LEN + IPV6_HEADER_LEN,
        IPV6_MIN_MTU,
        "Total unfragmented packet size must exactly equal IPv6 minimum MTU (1280 octets)"
    );

    // FRAME_QUANTA invariants
    assert_eq!(FRAME_QUANTA, [256, 512, 1232]);
}

#[test]
fn test_build_data_frame_directed_boundary_enforcement() {
    let key = FrameKey::from_slice(&[0x42u8; 32]);

    // Exact maximum capacity: 1205 octets
    let max_payload = vec![0x7Au8; MAX_PAYLOAD];
    let frame_max = build_data_frame_directed(&key, 100, DIR_SEND, DEFAULT_WIRE_QUANTUM, &max_payload)
        .expect("1205-byte payload must fit into 1232-byte wire quantum");
    assert_eq!(frame_max.len(), DEFAULT_WIRE_QUANTUM);

    // Overflow boundary: 1206 octets must be rejected fail-closed
    let overflow_payload = vec![0x7Au8; MAX_PAYLOAD + 1];
    let overflow_res = build_data_frame_directed(&key, 101, DIR_SEND, DEFAULT_WIRE_QUANTUM, &overflow_payload);
    assert!(
        overflow_res.is_err(),
        "1206-byte payload must fail to fit in 1232-byte wire quantum"
    );

    // Smaller quantum test: 100 bytes into 256 quantum
    let small_payload = vec![0x33u8; 100];
    let frame_small = build_data_frame_directed(&key, 102, DIR_SEND, 256, &small_payload)
        .expect("100-byte payload must fit into 256-byte quantum");
    assert_eq!(frame_small.len(), 256);
}
