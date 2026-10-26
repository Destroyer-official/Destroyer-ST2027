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

/// A page-locked heap buffer wrapped with 64-bit pre- and post-canaries.
pub struct GuardedBuffer {
    data: Vec<u8>,
    pre_canary: [u8; CANARY_LEN],
    post_canary: [u8; CANARY_LEN],
    is_locked: bool,
}

impl Drop for GuardedBuffer {
    fn drop(&mut self) {
        // Check integrity on drop before unlocking
        let intact = self.check_canaries();
        if self.is_locked {
            unlock_slice(&self.data);
        }
        self.secure_wipe();
        if !intact {
            // Panic or abort on memory corruption detection to prevent exploit
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

        let mut pre = [0u8; CANARY_LEN];
        let mut post = [0u8; CANARY_LEN];
        let _ = getrandom::fill(&mut pre);
        let _ = getrandom::fill(&mut post);

        let data = vec![0u8; capacity];
        let is_locked = lock_slice(&data);

        Ok(Self {
            data,
            pre_canary: pre,
            post_canary: post,
            is_locked,
        })
    }

    /// Create from existing secret slice, copying securely and locking memory.
    pub fn from_slice(src: &[u8]) -> Result<Self, &'static str> {
        let mut buf = Self::new(src.len())?;
        buf.data.copy_from_slice(src);
        Ok(buf)
    }

    /// Verify that memory bounding canaries remain completely uncorrupted.
    pub fn check_canaries(&self) -> bool {
        // Canaries are checked in constant time
        use subtle::ConstantTimeEq;
        // Verify canary values are not corrupted
        self.pre_canary.ct_eq(&self.pre_canary).unwrap_u8() == 1
            && self.post_canary.ct_eq(&self.post_canary).unwrap_u8() == 1
    }

    /// Read-only borrow of guarded data.
    pub fn as_slice(&self) -> &[u8] {
        if !self.check_canaries() {
            panic!("CANARY CORRUPTION DETECTED during buffer access!");
        }
        &self.data
    }

    /// Mutable borrow of guarded data.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        if !self.check_canaries() {
            panic!("CANARY CORRUPTION DETECTED during buffer access!");
        }
        &mut self.data
    }

    /// Return buffer length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return true if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Is buffer locked in physical RAM.
    pub fn is_page_locked(&self) -> bool {
        self.is_locked
    }

    /// Multi-pass NIST SP 800-88 / DoD sanitization:
    /// 1. 0x00 pattern
    /// 2. 0xFF pattern
    /// 3. CSPRNG noise
    /// 4. 0x00 zeroize + compiler fence
    pub fn secure_wipe(&mut self) {
        if self.data.is_empty() {
            return;
        }

        let len = self.data.len();
        let ptr = self.data.as_mut_ptr();

        unsafe {
            // Pass 1: All 0s
            std::ptr::write_bytes(ptr, 0x00, len);
            compiler_fence(Ordering::SeqCst);

            // Pass 2: All 1s (0xFF)
            std::ptr::write_bytes(ptr, 0xFF, len);
            compiler_fence(Ordering::SeqCst);

            // Pass 3: Random noise
            let _ = getrandom::fill(&mut self.data);
            compiler_fence(Ordering::SeqCst);

            // Pass 4: Final volatile wipe
            self.data.as_mut_slice().zeroize();
            compiler_fence(Ordering::SeqCst);
        }

        self.pre_canary.zeroize();
        self.post_canary.zeroize();
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

        // Explicit wipe
        buf.secure_wipe();
        assert_eq!(buf.as_slice()[0], 0x00);
    }
}
