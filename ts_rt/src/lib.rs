//! ts_rt — deterministic Top-Secret runtime core.
//!
//! Guarantees by construction (no garbage collector, no bytecode VM, no
//! external dependencies — not even libc-level crates):
//!   - secrets live in OS-locked pages (VirtualLock / mlock), never pageable;
//!   - every secret buffer is volatile-wiped on free (compiler fence included);
//!   - replay bitmap + constant-time compare are branchless over secrets;
//!   - `panic = "abort"` in release: no unwinding across the FFI boundary.
//!
//! Discipline: `#![deny(unsafe_op_in_unsafe_fn)]`; every `unsafe` block
//! carries a SAFETY comment (Ferrocene safety-manual style). `unsafe` is
//! confined to: raw-pointer alloc/free, volatile wipe, and OS lock calls.

#![deny(unsafe_op_in_unsafe_fn)]

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

const MAX_LOCKED_BYTES: usize = 64 << 20; // 64 MiB per buffer, DoS bound
const REPLAY_WINDOW: u64 = 64;

#[cfg(windows)]
#[link(name = "kernel32")]
extern "C" {
    fn VirtualLock(lpaddress: *mut core::ffi::c_void, dwsize: usize) -> c_int;
    fn VirtualUnlock(lpaddress: *mut core::ffi::c_void, dwsize: usize) -> c_int;
}

#[cfg(not(windows))]
extern "C" {
    fn mlock(addr: *const core::ffi::c_void, len: usize) -> c_int;
    fn munlock(addr: *const core::ffi::c_void, len: usize) -> c_int;
}

fn lock_pages(p: *mut u8, size: usize) -> bool {
    if p.is_null() || size == 0 {
        return false;
    }
    // SAFETY: caller guarantees a live writable allocation of `size` bytes.
    unsafe {
        #[cfg(windows)]
        {
            VirtualLock(p as *mut core::ffi::c_void, size) != 0
        }
        #[cfg(not(windows))]
        {
            mlock(p as *const core::ffi::c_void, size) == 0
        }
    }
}

fn unlock_pages(p: *mut u8, size: usize) {
    if p.is_null() || size == 0 {
        return;
    }
    // SAFETY: caller guarantees a live locked allocation of `size` bytes.
    unsafe {
        #[cfg(windows)]
        {
            VirtualUnlock(p as *mut core::ffi::c_void, size);
        }
        #[cfg(not(windows))]
        {
            munlock(p as *const core::ffi::c_void, size);
        }
    }
}

/// Volatile wipe: the compiler may neither elide nor reorder this loop past
/// the fence. Every secret buffer passes through here before release.
fn volatile_zero(dst: *mut u8, len: usize) {
    if dst.is_null() {
        return;
    }
    // SAFETY: caller guarantees `len` writable bytes at `dst`.
    unsafe {
        let mut i = 0usize;
        while i < len {
            ptr::write_volatile(dst.add(i), 0);
            i += 1;
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Allocate a zeroed, OS-locked buffer. NULL on any failure (fail-closed:
/// callers must never fall back to unlocked memory for secrets).
#[no_mangle]
pub extern "C" fn tsrt_alloc_locked(size: usize) -> *mut u8 {
    if size == 0 || size > MAX_LOCKED_BYTES {
        return ptr::null_mut();
    }
    let layout = match Layout::from_size_align(size, 1) {
        Ok(l) => l,
        Err(_) => return ptr::null_mut(),
    };
    // SAFETY: layout is non-zero by construction.
    let p = unsafe { alloc_zeroed(layout) };
    if p.is_null() {
        return ptr::null_mut();
    }
    if !lock_pages(p, size) {
        // SAFETY: `p` came from `alloc_zeroed` with this layout.
        unsafe { dealloc(p, layout) };
        return ptr::null_mut();
    }
    p
}

/// Fill a buffer with one byte (test/fill helper; bounds-checked).
#[no_mangle]
pub extern "C" fn tsrt_write(ptr: *mut u8, size: usize, value: c_uchar) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    if size == 0 || size > MAX_LOCKED_BYTES {
        return -1;
    }
    // SAFETY: caller guarantees `size` writable bytes; bounds checked above.
    unsafe {
        ptr::write_bytes(ptr, value, size);
        compiler_fence(Ordering::SeqCst);
    }
    0
}

/// Volatile-wipe + unlock + free. NULL/size-0 are safe no-ops.
#[no_mangle]
pub extern "C" fn tsrt_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 || size > MAX_LOCKED_BYTES {
        return;
    }
    volatile_zero(ptr, size);
    unlock_pages(ptr, size);
    if let Ok(layout) = Layout::from_size_align(size, 1) {
        // SAFETY: paired with `alloc_zeroed` in `tsrt_alloc_locked`.
        unsafe { dealloc(ptr, layout) };
    }
}

/// Constant-time equality: 1 equal, 0 different, -1 on null pointers.
/// Length mismatch short-circuits on LENGTH ONLY (never on content).
#[no_mangle]
pub extern "C" fn tsrt_ct_eq(a: *const u8, a_len: usize, b: *const u8, b_len: usize) -> c_int {
    if a.is_null() || b.is_null() {
        return -1;
    }
    if a_len != b_len {
        return 0;
    }
    let mut acc: u8 = 0;
    let mut i = 0usize;
    while i < a_len {
        // SAFETY: non-null pointers, `i < a_len == b_len`, in-bounds.
        unsafe {
            acc |= ptr::read_volatile(a.add(i)) ^ ptr::read_volatile(b.add(i));
        }
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
    (acc == 0) as c_int
}

/// Monotonic replay window (u64 bitmap, WireGuard mechanism family).
#[repr(C)]
pub struct TsrtReplay {
    base: u64,
    bitmap: u64,
}

#[no_mangle]
pub extern "C" fn tsrt_replay_new(start: u64) -> *mut TsrtReplay {
    let r = Box::new(TsrtReplay { base: start, bitmap: 1 });
    Box::into_raw(r)
}

/// Read-only verdict: 1 = acceptable, 0 = replay/stale. Never mutates.
/// MUST be called on unauthenticated input; state advances only via
/// `tsrt_replay_mark` after AEAD authentication (RFC 6479: "If S>WT
/// and is validated, the window is advanced"; WireGuard Sec 5.4:
/// counters "checked only after having verified the authentication
/// tag").
#[inline]
fn replay_check(st: &TsrtReplay, seq: u64) -> bool {
    if seq < st.base {
        return false;
    }
    let off = seq.wrapping_sub(st.base);
    if off < REPLAY_WINDOW {
        let bit = 1u64 << off;
        if st.bitmap & bit != 0 {
            return false;
        }
    }
    true
}

/// Advance window for a validated seq. Idempotent for duplicates and
/// no-op for seq < base (unreachable when called after successful
/// `replay_check` + AEAD auth; safe by construction).
#[inline]
fn replay_mark(st: &mut TsrtReplay, seq: u64) {
    if seq < st.base {
        return;
    }
    let off = seq.wrapping_sub(st.base);
    if off < REPLAY_WINDOW {
        let bit = 1u64 << off;
        st.bitmap |= bit;
        return;
    }
    let shift = off - (REPLAY_WINDOW - 1);
    if shift >= REPLAY_WINDOW {
        st.bitmap = 0;
    } else {
        st.bitmap >>= shift;
    }
    st.base += shift;
    st.bitmap |= 1u64 << (REPLAY_WINDOW - 1);
}

/// 1 = accept (read-only, no state change), 0 = replay/reorder reject,
/// -1 = null handle.
#[no_mangle]
pub extern "C" fn tsrt_replay_check(r: *const TsrtReplay, seq: u64) -> c_int {
    if r.is_null() {
        return -1;
    }
    // SAFETY: handle came from `tsrt_replay_new`; shared borrow performs
    // no mutation, so calling on unauthenticated input is safe.
    let st = unsafe { &*r };
    if replay_check(st, seq) {
        1
    } else {
        0
    }
}

/// 1 = marked (or no-op for seq < base), -1 = null handle. Call ONLY
/// after `tsrt_replay_check` accepted AND the AEAD tag for that exact
/// seq verified.
#[no_mangle]
pub extern "C" fn tsrt_replay_mark(r: *mut TsrtReplay, seq: u64) -> c_int {
    if r.is_null() {
        return -1;
    }
    // SAFETY: handle came from `tsrt_replay_new`; single-owner discipline
    // is the caller's contract (same as the Python implementation).
    let st = unsafe { &mut *r };
    replay_mark(st, seq);
    1
}

/// 1 = accept, 0 = replay/reorder reject, -1 = null handle.
/// Retained for backward compatibility (non-wire atomic helper / tests).
/// Wire paths MUST use check-then-AEAD-then-mark instead.
#[no_mangle]
pub extern "C" fn tsrt_replay_check_mark(r: *mut TsrtReplay, seq: u64) -> c_int {
    if r.is_null() {
        return -1;
    }
    // SAFETY: handle came from `tsrt_replay_new`; single-owner discipline
    // is the caller's contract (same as the Python implementation).
    let st = unsafe { &mut *r };
    if !replay_check(st, seq) {
        return 0;
    }
    replay_mark(st, seq);
    1
}

#[no_mangle]
pub extern "C" fn tsrt_replay_free(r: *mut TsrtReplay) {
    if r.is_null() {
        return;
    }
    // SAFETY: handle came from `tsrt_replay_new`; wipe state before release.
    unsafe {
        volatile_zero(r as *mut u8, core::mem::size_of::<TsrtReplay>());
        drop(Box::from_raw(r));
    }
}

static VERSION: &str = concat!("ts_rt 1.0.0 [", env!("TSRT_RUSTC"), "]\0");

#[no_mangle]
pub extern "C" fn tsrt_version() -> *const c_char {
    // SAFETY: VERSION is a 'static byte string with an explicit NUL
    // terminator (see concat! above); the pointer stays valid forever.
    // (A previous revision omitted the NUL and over-read — caught in audit.)
    VERSION.as_ptr() as *const c_char
}

/// Built-in self-test. 0 = pass; otherwise the failing step number.
/// Steps: 1 locked alloc/write/free, 2 ct_eq, 3 replay vectors.
#[no_mangle]
pub extern "C" fn tsrt_selftest() -> c_int {
    // Step 1: locked buffer roundtrip.
    let p = tsrt_alloc_locked(64);
    if p.is_null() {
        return 1;
    }
    if tsrt_write(p, 64, 0xA5) != 0 {
        tsrt_free(p, 64);
        return 1;
    }
    // SAFETY: just allocated 64 readable bytes above.
    let ok = unsafe { std::slice::from_raw_parts(p, 64).iter().all(|&b| b == 0xA5) };
    tsrt_free(p, 64);
    if !ok {
        return 1;
    }
    // Step 2: constant-time compare vectors.
    let a = [0x01u8, 0x02, 0x03, 0x04];
    let b = [0x01u8, 0x02, 0x03, 0x04];
    let c = [0x01u8, 0x02, 0x03, 0x05];
    if tsrt_ct_eq(a.as_ptr(), 4, b.as_ptr(), 4) != 1 {
        return 2;
    }
    if tsrt_ct_eq(a.as_ptr(), 4, c.as_ptr(), 4) != 0 {
        return 2;
    }
    if tsrt_ct_eq(a.as_ptr(), 4, c.as_ptr(), 3) != 0 {
        return 2;
    }
    if tsrt_ct_eq(core::ptr::null(), 4, b.as_ptr(), 4) != -1 {
        return 2;
    }
    // Step 3: replay vectors (in-order / dup / behind / jump-ahead resync).
    let r = tsrt_replay_new(1000);
    if r.is_null() {
        return 3;
    }
    let v = [
        (1001u64, 1),
        (1000, 0), // duplicate
        (999, 0),  // below base
        (1063, 1), // window edge (off 63)
        (1064, 1), // slide by one
        (1000, 0), // now below slid base
        (5000, 1), // jump-ahead resync
        (5000, 0), // duplicate after resync
    ];
    for (seq, want) in v {
        if tsrt_replay_check_mark(r, seq) != want {
            tsrt_replay_free(r);
            return 3;
        }
    }
    // Step 3b: split check/mark decoupling — check is read-only, mark
    // advances only after validation (window-poisoning defense).
    let r2 = tsrt_replay_new(5000);
    if r2.is_null() {
        tsrt_replay_free(r);
        return 3;
    }
    // 5000 seen at construction; 99999 unseen.
    if tsrt_replay_check(r2, 99999) != 1 {
        tsrt_replay_free(r);
        tsrt_replay_free(r2);
        return 3;
    }
    // Read-only: second check of same seq still accepts (not consumed).
    if tsrt_replay_check(r2, 99999) != 1 {
        tsrt_replay_free(r);
        tsrt_replay_free(r2);
        return 3;
    }
    // Window unmoved by checks: an in-window unseen seq still accepts.
    if tsrt_replay_check(r2, 5001) != 1 {
        tsrt_replay_free(r);
        tsrt_replay_free(r2);
        return 3;
    }
    if tsrt_replay_mark(r2, 99999) != 1 {
        tsrt_replay_free(r);
        tsrt_replay_free(r2);
        return 3;
    }
    // After mark: consumed seq rejects, slid-past seq rejects.
    if tsrt_replay_check(r2, 99999) != 0 {
        tsrt_replay_free(r);
        tsrt_replay_free(r2);
        return 3;
    }
    if tsrt_replay_check(r2, 5001) != 0 {
        tsrt_replay_free(r);
        tsrt_replay_free(r2);
        return 3;
    }
    if tsrt_replay_check(core::ptr::null(), 1) != -1 {
        tsrt_replay_free(r);
        tsrt_replay_free(r2);
        return 3;
    }
    if tsrt_replay_mark(core::ptr::null_mut(), 1) != -1 {
        tsrt_replay_free(r);
        tsrt_replay_free(r2);
        return 3;
    }
    tsrt_replay_free(r2);
    tsrt_replay_free(r);
    0
}
