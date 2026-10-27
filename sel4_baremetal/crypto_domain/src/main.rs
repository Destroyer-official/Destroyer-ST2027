//! Bare-Metal seL4 Microkit CRYPTO Protection Domain (Sovereign Core)
//! ====================================================================
//! Executes with `#![no_std]` and `#![no_main]`.
//! Zero dynamic allocations, zero heap, zero libc/OS runtime.
//!
//! Dual-Boundary Mappings (per system.xml):
//! - `0x10000000`: RED <-> CRYPTO shared-memory ring (plaintext)
//! - `0x20000000`: CRYPTO <-> BLACK shared-memory ring (ciphertext)
//! - `0x30000000`: Isolated key storage page (quarantined to this domain)
//!
//! Notifications:
//! - Channel 1: RED domain event
//! - Channel 2: BLACK domain event

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

pub const RED_CRYPTO_RING_VADDR: usize = 0x10000000;
pub const CRYPTO_BLACK_RING_VADDR: usize = 0x20000000;
pub const CRYPTO_LOCKED_KEYS_VADDR: usize = 0x30000000;

pub const CHANNEL_RED: usize = 1;
pub const CHANNEL_BLACK: usize = 2;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Fail-closed emergency wipe on unrecoverable panic
    emergency_wipe_keys();
    loop {
        core::hint::spin_loop();
    }
}

/// Volatile multi-pass memory wipe for secret key storage page.
#[inline(never)]
pub fn emergency_wipe_keys() {
    let key_ptr = CRYPTO_LOCKED_KEYS_VADDR as *mut u8;
    for i in 0..0x4000 {
        unsafe {
            ptr::write_volatile(key_ptr.add(i), 0xAA);
        }
    }
    compiler_fence(Ordering::SeqCst);
    for i in 0..0x4000 {
        unsafe {
            ptr::write_volatile(key_ptr.add(i), 0x00);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn init() {
    compiler_fence(Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn notified(channel: usize) {
    match channel {
        CHANNEL_RED => {
            // Read outbound plaintext, encrypt under ratchet, push to black ring
            compiler_fence(Ordering::SeqCst);
        }
        CHANNEL_BLACK => {
            // Read inbound ciphertext, authenticate, decrypt, push to red ring
            compiler_fence(Ordering::SeqCst);
        }
        _ => {}
    }
}
