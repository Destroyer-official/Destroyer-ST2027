//! OS page-locking for secret buffers (VirtualLock / mlock).
//!
//! Ported pattern from `ts_rt` (zero new dependencies: kernel32 on Windows,
//! libc on Unix — both already linked by every binary here).
//!
//! Best-effort by design: locking can fail under quota/privilege limits
//! (Linux `RLIMIT_MEMLOCK`, Windows working-set quota). Callers MUST treat
//! `false` as "unlocked, proceed with wipe-only hygiene" — hard refusal on
//! lock failure lives in the Python TS gates, never here (bricking field
//! binaries over rlimits would be a self-inflicted DoS).
//!
//! Drop order is load-bearing: [`LockedKey32::drop`] unlocks first, then the
//! `Box<Zeroizing<..>>` field drop wipes the bytes. Unlock-before-wipe keeps
//! no locked dead pages behind.

use std::os::raw::{c_int, c_void};

use zeroize::Zeroizing;

#[cfg(windows)]
#[link(name = "kernel32")]
extern "C" {
    fn VirtualLock(lpaddress: *mut c_void, dwsize: usize) -> c_int;
    fn VirtualUnlock(lpaddress: *mut c_void, dwsize: usize) -> c_int;
}

#[cfg(not(windows))]
extern "C" {
    fn mlock(addr: *const c_void, len: usize) -> c_int;
    fn munlock(addr: *const c_void, len: usize) -> c_int;
}

/// Best-effort page-lock of a live borrow. Empty slices refuse
/// (fail-closed on nonsense input). Never panics.
pub fn lock_slice(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    let (ptr, len) = (buf.as_ptr(), buf.len());
    // SAFETY: ptr/len describe a live shared borrow for this call only;
    // neither OS call retains the pointer or writes through it.
    unsafe {
        #[cfg(windows)]
        {
            VirtualLock(ptr as *mut c_void, len) != 0
        }
        #[cfg(not(windows))]
        {
            mlock(ptr as *const c_void, len) == 0
        }
    }
}

/// Best-effort unlock. Never panics; unlocking an unlocked range is
/// ignored by the OS (error return discarded deliberately).
pub fn unlock_slice(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    let (ptr, len) = (buf.as_ptr(), buf.len());
    // SAFETY: same borrow discipline as lock_slice.
    unsafe {
        #[cfg(windows)]
        {
            VirtualUnlock(ptr as *mut c_void, len);
        }
        #[cfg(not(windows))]
        {
            munlock(ptr as *const c_void, len);
        }
    }
}

/// 32-byte frame secret: heap-stable address, page-locked (best-effort),
/// wiped on drop. Heap-boxed so the locked address never moves (no `Vec`
/// realloc hazard); `Zeroizing` wipes on drop after we unlock.
pub struct LockedKey32 {
    inner: Box<Zeroizing<[u8; 32]>>,
    locked: bool,
}

impl LockedKey32 {
    /// Move key bytes into a locked box. The caller's source array is NOT
    /// touched (it was moved-from by value) — the caller must still wipe
    /// its own copy, exactly as before.
    pub fn new(bytes: [u8; 32]) -> Self {
        let inner = Box::new(Zeroizing::new(bytes));
        let locked = lock_slice(&inner[..]);
        Self { inner, locked }
    }

    /// Parse hex directly into a page-locked, zeroized container,
    /// avoiding any intermediate secret copy on the stack.
    pub fn from_hex(hex: &str) -> Result<Self, &'static str> {
        let clean = hex.trim();
        if clean.len() != 64 {
            return Err("key must be exactly 64 hex characters (32 bytes)");
        }
        let mut inner = Box::new(Zeroizing::new([0u8; 32]));
        let locked = lock_slice(&inner[..]);
        for (i, chunk) in clean.as_bytes().chunks_exact(2).enumerate() {
            let s = std::str::from_utf8(chunk).map_err(|_| "bad hex encoding")?;
            inner[i] = u8::from_str_radix(s, 16).map_err(|_| "bad hex digit")?;
        }
        Ok(Self { inner, locked })
    }

    /// Borrow the secret for a single copy-out. Keep the borrow short:
    /// every extra live copy is a wiping liability.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }

    /// Whether the OS accepted the page lock. `false` means wipe-only
    /// hygiene is in effect (logged by the caller, never fatal here).
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for LockedKey32 {
    fn drop(&mut self) {
        if self.locked {
            unlock_slice(&self.inner[..]);
            self.locked = false;
        }
        // Box<Zeroizing<[u8; 32]>> field drop wipes the bytes next.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_slice_lock_refused() {
        assert!(!lock_slice(&[]));
        unlock_slice(&[]); // must not panic
    }

    #[test]
    fn lock_unlock_roundtrip_no_panic() {
        let buf = [0xA5u8; 64];
        // Best-effort: assert the call discipline completes, not OS success
        // (sandbox rlimits must never fail a unit test).
        let _ = lock_slice(&buf);
        unlock_slice(&buf);
        unlock_slice(&buf); // double-unlock tolerated
    }

    #[test]
    fn guard_preserves_bytes_and_reports_state() {
        let raw = [0x5Au8; 32];
        let guard = LockedKey32::new(raw);
        assert_eq!(guard.as_bytes(), &raw);
        assert_eq!(guard.as_bytes().len(), 32);
        // State flag is a bool reflecting the single lock attempt above.
        let _ = guard.is_locked();
    }

    #[test]
    fn guard_drop_without_panic() {
        {
            let _guard = LockedKey32::new([0x01u8; 32]);
            // Guard drops here: unlock-then-wipe, no panic.
        }
        // Post-drop the allocator is undisturbed: fresh lock discipline works.
        let buf = [0x02u8; 32];
        let _ = lock_slice(&buf);
        unlock_slice(&buf);
    }
}
