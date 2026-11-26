//! Hardware & Memory Protection Engine (Stack Canaries & Secure Guard Buffers).
//!
//! Provides defense-in-depth against memory corruption, buffer overflows, and cold-boot extraction:
//! - 64-bit CSPRNG Stack Canaries framing sensitive memory buffers.
//! - VirtualLock / mlock OS page-locking preventing paging to disk / swap.
//! - Multi-pass DoD 5220.22-M / NIST SP 800-88 cryptographic memory sanitization.
//! - Immediate detection of buffer overrun/underrun triggering fail-closed purge.

use crate::memlock::{lock_slice, unlock_slice};
use std::sync::atomic::{compiler_fence, Ordering};
use zeroize::Zeroize;

pub const CANARY_LEN: usize = 8;

/// A page-locked contiguous heap buffer with 64-bit pre- and post-canaries
/// bordering the payload allocation (`[pre_canary | payload | post_canary]`).
pub struct GuardedBuffer {
    slab: Vec<u8>,
    payload_len: usize,
    expected_pre: [u8; CANARY_LEN],
    expected_post: [u8; CANARY_LEN],
    is_locked: bool,
}

impl Drop for GuardedBuffer {
    fn drop(&mut self) {
        // Check live border canaries against expected reference BEFORE unlocking/wiping.
        let intact = self.check_canaries();
        self.secure_wipe();
        self.slab.zeroize();
        self.expected_pre.zeroize();
        self.expected_post.zeroize();
        if self.is_locked {
            unlock_slice(&self.slab);
        }
        if !intact {
            eprintln!(
                "CRITICAL SECURITY ALERT: GuardedBuffer canary corruption detected! Memory wiped."
            );
        }
    }
}

impl GuardedBuffer {
    /// Allocate a guarded, page-locked buffer initialized with zeros.
    pub fn new(capacity: usize) -> Result<Self, &'static str> {
        if capacity == 0 || capacity > (64 << 20) {
            return Err("invalid buffer size");
        }
        let total_len = capacity
            .checked_add(CANARY_LEN * 2)
            .ok_or("buffer size overflow")?;

        let mut expected_pre = [0u8; CANARY_LEN];
        let mut expected_post = [0u8; CANARY_LEN];
        if getrandom::fill(&mut expected_pre).is_err()
            || getrandom::fill(&mut expected_post).is_err()
        {
            return Err("csprng failure initializing buffer canaries");
        }

        let mut slab = vec![0u8; total_len];
        slab[..CANARY_LEN].copy_from_slice(&expected_pre);
        slab[CANARY_LEN + capacity..].copy_from_slice(&expected_post);
        let is_locked = lock_slice(&slab);

        Ok(Self {
            slab,
            payload_len: capacity,
            expected_pre,
            expected_post,
            is_locked,
        })
    }

    /// Create from existing secret slice, copying securely and locking memory.
    pub fn from_slice(src: &[u8]) -> Result<Self, &'static str> {
        let mut buf = Self::new(src.len())?;
        buf.slab[CANARY_LEN..CANARY_LEN + src.len()].copy_from_slice(src);
        Ok(buf)
    }

    /// Verify live memory border canaries against independent expected values in constant time.
    pub fn check_canaries(&self) -> bool {
        use subtle::ConstantTimeEq;
        if self.slab.len() < self.payload_len + CANARY_LEN * 2 {
            return false;
        }
        let live_pre = &self.slab[..CANARY_LEN];
        let live_post = &self.slab[CANARY_LEN + self.payload_len..CANARY_LEN * 2 + self.payload_len];
        live_pre.ct_eq(&self.expected_pre).unwrap_u8() == 1
            && live_post.ct_eq(&self.expected_post).unwrap_u8() == 1
    }

    /// Read-only borrow of guarded data.
    pub fn as_slice(&self) -> &[u8] {
        if !self.check_canaries() {
            panic!("CANARY CORRUPTION DETECTED during buffer access!");
        }
        &self.slab[CANARY_LEN..CANARY_LEN + self.payload_len]
    }

    /// Mutable borrow of guarded data.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if !self.check_canaries() {
            panic!("CANARY CORRUPTION DETECTED during buffer access!");
        }
        let end = CANARY_LEN + self.payload_len;
        &mut self.slab[CANARY_LEN..end]
    }

    /// Return buffer length.
    pub fn len(&self) -> usize {
        self.payload_len
    }

    /// Return true if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.payload_len == 0
    }

    /// Is buffer locked in physical RAM.
    pub fn is_page_locked(&self) -> bool {
        self.is_locked
    }

    /// Multi-pass NIST SP 800-88 / DoD sanitization of payload bytes:
    /// 1. 0x00 pattern
    /// 2. 0xFF pattern
    /// 3. CSPRNG noise
    /// 4. 0x00 zeroize + compiler fence
    pub fn secure_wipe(&mut self) {
        if self.payload_len == 0 || self.slab.len() < CANARY_LEN + self.payload_len {
            return;
        }

        let payload = &mut self.slab[CANARY_LEN..CANARY_LEN + self.payload_len];
        let len = payload.len();
        let ptr = payload.as_mut_ptr();

        unsafe {
            // Pass 1: All 0s
            std::ptr::write_bytes(ptr, 0x00, len);
            compiler_fence(Ordering::SeqCst);

            // Pass 2: All 1s (0xFF)
            std::ptr::write_bytes(ptr, 0xFF, len);
            compiler_fence(Ordering::SeqCst);

            // Pass 3: Random noise
            let _ = getrandom::fill(payload);
            compiler_fence(Ordering::SeqCst);

            // Pass 4: Final volatile wipe
            payload.zeroize();
            compiler_fence(Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guarded_buffer_lifecycle() {
        let secret = b"TOP_SECRET_COMMUNICATION_KEY_123";
        let mut buf = GuardedBuffer::from_slice(secret).expect("alloc");
        assert_eq!(buf.len(), secret.len());
        assert_eq!(buf.as_slice(), secret);
        assert!(buf.check_canaries());

        // Mutate securely
        buf.as_mut_slice()[0] = b'X';
        assert_eq!(buf.as_slice()[0], b'X');

        // Explicit wipe zeroes payload while preserving guard structure until drop
        buf.secure_wipe();
        assert!(buf.check_canaries());
        assert_eq!(buf.as_slice()[0], 0x00);
    }

    #[test]
    fn test_guarded_buffer_detects_overrun_and_underrun_corruption() {
        let mut buf = GuardedBuffer::from_slice(b"SECRET123").expect("alloc");
        assert!(buf.check_canaries());

        // Simulate buffer underrun corrupting the adjacent live pre-canary byte
        buf.slab[CANARY_LEN - 1] ^= 0xFF;
        assert!(!buf.check_canaries(), "pre-canary corruption must be detected");
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = buf.as_slice();
        }))
        .is_err();
        assert!(panicked, "as_slice must panic on pre-canary corruption");

        // Restore pre-canary and corrupt post-canary border byte (buffer overrun)
        buf.slab[CANARY_LEN - 1] ^= 0xFF;
        let post_idx = CANARY_LEN + buf.len();
        buf.slab[post_idx] ^= 0x5A;
        assert!(!buf.check_canaries(), "post-canary corruption must be detected");
        buf.slab[post_idx] ^= 0x5A;
        assert!(buf.check_canaries());
    }
}
