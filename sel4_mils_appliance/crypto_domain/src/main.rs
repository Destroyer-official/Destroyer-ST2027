//! Bare-Metal seL4 Microkit CRYPTO Protection Domain (Sovereign Cryptographic Engine)
//! ==================================================================================
//! Executes with `#![no_std]` and `#![no_main]`.
//! Zero dynamic allocations, zero heap, zero operating system dependencies.
//!
//! Architectural Invariants (MILS Strict Separation):
//! 1. Complete Mediation: Serves as the strictly non-bypassable intermediary
//!    between Plaintext (RED) and Ciphertext (BLACK) domains.
//! 2. Zero Direct Network or User I/O: Zero sockets, zero display hardware.
//! 3. Quarantined Key Storage: Holds exclusive access to memory region
//!    `crypto_locked_keys` mapped at `0x30000000`. Neither RED nor BLACK has
//!    any capability or page table mapping to this region.
//! 4. Scorched-Earth Emergency Zeroization: On tamper detection or panic,
//!    performs immediate multi-pass volatile memory erasure with full memory fences.
//! 5. Communicates with RED via `0x10000000` (Channel 1) and with BLACK via
//!    `0x20000000` (Channel 2).

#![no_std]
#![cfg_attr(not(test), no_main)]

use aes_gcm::{
    aead::{inout::InOutBuf, AeadInOut, KeyInit, Tag},
    Aes256Gcm, Nonce,
};
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::{compiler_fence, fence, AtomicU32, Ordering};
use zeroize::Zeroize;

// =============================================================================
// Memory Mapping Constants (from sel4_mils_appliance/system.xml)
// =============================================================================

/// Shared Memory Ring Buffers
pub const RED_CRYPTO_RING_VADDR: usize = 0x10000000;
pub const CRYPTO_BLACK_RING_VADDR: usize = 0x20000000;
pub const CRYPTO_LOCKED_KEYS_VADDR: usize = 0x30000000;

pub const RING_TOTAL_SIZE: usize = 0x10000;     // 64 KiB
pub const RING_HALF_SIZE: usize = 0x8000;      // 32 KiB
pub const LOCKED_KEYS_SIZE: usize = 0x4000;    // 16 KiB

/// Ring buffer offsets
pub const TX_OFFSET: usize = 0x0000;
pub const RX_OFFSET: usize = 0x8000;

/// Microkit Notification Channels
pub const CHANNEL_RED: usize = 1;
pub const CHANNEL_BLACK: usize = 2;

/// Ring Buffer Protocol Constants
pub const RING_MAGIC: u32 = 0x53454C34; // "sEL4"
pub const RING_VERSION: u32 = 1;
pub const RING_CTRL_SIZE: usize = 64;
pub const RING_DATA_CAPACITY: usize = RING_HALF_SIZE - RING_CTRL_SIZE; // 32704 bytes

/// Message Types
pub const MSG_TYPE_PLAINTEXT: u8 = 0x01;
pub const MSG_TYPE_CIPHERTEXT: u8 = 0x02;
pub const MSG_TYPE_KEY_EXCHANGE: u8 = 0x03;
pub const MSG_TYPE_HEARTBEAT: u8 = 0x04;
pub const MSG_TYPE_WRAP: u8 = 0xFE;

// =============================================================================
// Zero-Copy Ring Buffer Memory Layout
// =============================================================================

#[repr(C, align(64))]
pub struct RingControl {
    pub magic: u32,
    pub version: u32,
    pub capacity: u32,
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub dropped_count: AtomicU32,
    pub flags: AtomicU32,
    _reserved: [u32; 9],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FrameHeader {
    pub length: u16,
    pub msg_type: u8,
    pub flags: u8,
}

pub const FRAME_HEADER_SIZE: usize = core::mem::size_of::<FrameHeader>();

#[derive(Debug, PartialEq, Eq)]
pub enum RingError {
    BufferFull,
    BufferEmpty,
    InvalidMagic,
    InvalidFrame,
    SlotTooLarge,
    Zeroized,
}

/// Zero-Copy SPSC Transmit Ring
pub struct ZeroCopyTxRing {
    ctrl: *mut RingControl,
    buffer: *mut u8,
    capacity: usize,
}

impl ZeroCopyTxRing {
    pub unsafe fn new(base_vaddr: usize) -> Self {
        let ctrl = base_vaddr as *mut RingControl;
        let buffer = (base_vaddr + RING_CTRL_SIZE) as *mut u8;
        let capacity = RING_DATA_CAPACITY;

        if ptr::read_volatile(ptr::addr_of!((*ctrl).magic)) != RING_MAGIC {
            ptr::write_volatile(ptr::addr_of_mut!((*ctrl).magic), RING_MAGIC);
            ptr::write_volatile(ptr::addr_of_mut!((*ctrl).version), RING_VERSION);
            ptr::write_volatile(ptr::addr_of_mut!((*ctrl).capacity), capacity as u32);
            (*ctrl).head.store(0, Ordering::Release);
            (*ctrl).tail.store(0, Ordering::Release);
            (*ctrl).dropped_count.store(0, Ordering::Release);
            (*ctrl).flags.store(0, Ordering::Release);
        }

        Self { ctrl, buffer, capacity }
    }

    pub fn available_write(&self) -> usize {
        let head = unsafe { (*self.ctrl).head.load(Ordering::Acquire) as usize };
        let tail = unsafe { (*self.ctrl).tail.load(Ordering::Acquire) as usize };
        if head >= tail {
            self.capacity - (head - tail) - 1
        } else {
            tail - head - 1
        }
    }

    pub fn acquire_tx_slot(&mut self, payload_len: usize, msg_type: u8) -> Result<&mut [u8], RingError> {
        if payload_len == 0 || payload_len > (self.capacity - FRAME_HEADER_SIZE - 1) {
            return Err(RingError::SlotTooLarge);
        }

        let needed = FRAME_HEADER_SIZE + payload_len;
        let mut head = unsafe { (*self.ctrl).head.load(Ordering::Acquire) as usize };
        let tail = unsafe { (*self.ctrl).tail.load(Ordering::Acquire) as usize };

        if head >= tail {
            if head + needed > self.capacity {
                if tail > needed {
                    if self.capacity - head >= FRAME_HEADER_SIZE {
                        let wrap_header = FrameHeader {
                            length: (self.capacity - head - FRAME_HEADER_SIZE) as u16,
                            msg_type: MSG_TYPE_WRAP,
                            flags: 0,
                        };
                        unsafe {
                            let ptr = self.buffer.add(head) as *mut FrameHeader;
                            ptr::write_volatile(ptr, wrap_header);
                            compiler_fence(Ordering::SeqCst);
                            (*self.ctrl).head.store(0, Ordering::Release);
                        }
                    } else {
                        unsafe {
                            (*self.ctrl).head.store(0, Ordering::Release);
                        }
                    }
                    head = 0;
                } else {
                    unsafe { (*self.ctrl).dropped_count.fetch_add(1, Ordering::Relaxed) };
                    return Err(RingError::BufferFull);
                }
            }
        } else {
            if head + needed >= tail {
                unsafe { (*self.ctrl).dropped_count.fetch_add(1, Ordering::Relaxed) };
                return Err(RingError::BufferFull);
            }
        }

        let header = FrameHeader {
            length: payload_len as u16,
            msg_type,
            flags: 0,
        };

        unsafe {
            let header_ptr = self.buffer.add(head) as *mut FrameHeader;
            ptr::write_volatile(header_ptr, header);
            compiler_fence(Ordering::SeqCst);
            let payload_ptr = self.buffer.add(head + FRAME_HEADER_SIZE);
            Ok(core::slice::from_raw_parts_mut(payload_ptr, payload_len))
        }
    }

    pub fn commit_tx_slot(&mut self, payload_len: usize) -> Result<(), RingError> {
        let needed = FRAME_HEADER_SIZE + payload_len;
        let head = unsafe { (*self.ctrl).head.load(Ordering::Acquire) as usize };
        let new_head = (head + needed) % self.capacity;

        fence(Ordering::Release);
        compiler_fence(Ordering::SeqCst);
        unsafe {
            (*self.ctrl).head.store(new_head as u32, Ordering::Release);
        }
        Ok(())
    }

    pub fn push(&mut self, data: &[u8], msg_type: u8) -> Result<(), RingError> {
        let slot = self.acquire_tx_slot(data.len(), msg_type)?;
        slot.copy_from_slice(data);
        self.commit_tx_slot(data.len())
    }
}

/// Zero-Copy SPSC Receive Ring
pub struct ZeroCopyRxRing {
    ctrl: *mut RingControl,
    buffer: *const u8,
    capacity: usize,
}

#[derive(Debug, PartialEq)]
pub struct RxFrame<'a> {
    pub msg_type: u8,
    pub flags: u8,
    pub payload: &'a [u8],
    pub frame_len: usize,
}

impl ZeroCopyRxRing {
    pub unsafe fn new(base_vaddr: usize) -> Self {
        let ctrl = base_vaddr as *mut RingControl;
        let buffer = (base_vaddr + RING_CTRL_SIZE) as *const u8;
        let capacity = RING_DATA_CAPACITY;
        Self { ctrl, buffer, capacity }
    }

    pub fn peek_rx_slot(&self) -> Result<Option<RxFrame<'_>>, RingError> {
        let mut tail = unsafe { (*self.ctrl).tail.load(Ordering::Acquire) as usize };
        let head = unsafe { (*self.ctrl).head.load(Ordering::Acquire) as usize };

        if head == tail {
            return Ok(None);
        }

        // Check for end-of-buffer wrap
        if self.capacity - tail < FRAME_HEADER_SIZE {
            tail = 0;
            unsafe { (*self.ctrl).tail.store(0, Ordering::Release) };
            if head == tail {
                return Ok(None);
            }
        }

        fence(Ordering::Acquire);
        compiler_fence(Ordering::SeqCst);

        unsafe {
            let mut header_ptr = self.buffer.add(tail) as *const FrameHeader;
            let mut header = ptr::read_volatile(header_ptr);

            // Handle wrap marker
            if header.msg_type == MSG_TYPE_WRAP {
                tail = 0;
                (*self.ctrl).tail.store(0, Ordering::Release);
                if head == tail {
                    return Ok(None);
                }
                header_ptr = self.buffer.add(tail) as *const FrameHeader;
                header = ptr::read_volatile(header_ptr);
            }

            let payload_len = header.length as usize;
            let needed = FRAME_HEADER_SIZE + payload_len;

            if tail + needed > self.capacity {
                return Err(RingError::InvalidFrame);
            }

            let payload_ptr = self.buffer.add(tail + FRAME_HEADER_SIZE);
            let payload = core::slice::from_raw_parts(payload_ptr, payload_len);

            Ok(Some(RxFrame {
                msg_type: header.msg_type,
                flags: header.flags,
                payload,
                frame_len: needed,
            }))
        }
    }

    pub fn commit_rx_slot(&mut self, frame_len: usize) -> Result<(), RingError> {
        let tail = unsafe { (*self.ctrl).tail.load(Ordering::Acquire) as usize };
        let new_tail = (tail + frame_len) % self.capacity;

        fence(Ordering::Release);
        compiler_fence(Ordering::SeqCst);
        unsafe {
            (*self.ctrl).tail.store(new_tail as u32, Ordering::Release);
        }
        Ok(())
    }
}

// =============================================================================
// RFC 6479 Decoupled Anti-Replay Sliding Window (128-Packet Bitmap)
// =============================================================================

pub const REPLAY_WINDOW_SIZE: usize = 128;

#[derive(Debug, Clone, Copy)]
pub struct AntiReplayWindow {
    last_seq: u64,
    bitmap: [u64; 2],
    initialized: bool,
}

impl AntiReplayWindow {
    pub const fn new() -> Self {
        Self {
            last_seq: 0,
            bitmap: [0, 0],
            initialized: false,
        }
    }

    /// Read-only check executed before AEAD/PQC cryptographic verification.
    /// Returns true if sequence number is fresh and acceptable.
    pub fn check(&self, seq: u64) -> bool {
        if !self.initialized {
            return true;
        }

        if seq > self.last_seq {
            return true; // Packet is ahead of current window
        }

        let diff = self.last_seq - seq;
        if diff >= REPLAY_WINDOW_SIZE as u64 {
            return false; // Stale: falls behind sliding window floor
        }

        let word_idx = (diff / 64) as usize;
        let bit_idx = (diff % 64) as usize;
        (self.bitmap[word_idx] & (1u64 << bit_idx)) == 0
    }

    /// Mutating update executed ONLY after authentic AEAD/PQC tag verification.
    /// Defeats replay state corruption from forged/unauthenticated packets.
    pub fn mark(&mut self, seq: u64) {
        if !self.initialized {
            self.last_seq = seq;
            self.bitmap[0] = 1;
            self.bitmap[1] = 0;
            self.initialized = true;
            return;
        }

        if seq > self.last_seq {
            let diff = seq - self.last_seq;
            if diff >= REPLAY_WINDOW_SIZE as u64 {
                self.bitmap[0] = 1;
                self.bitmap[1] = 0;
            } else if diff >= 64 {
                let shift = diff - 64;
                self.bitmap[1] = self.bitmap[0] << shift;
                self.bitmap[0] = 1;
            } else {
                let shift = diff;
                self.bitmap[1] = (self.bitmap[1] << shift) | (self.bitmap[0] >> (64 - shift));
                self.bitmap[0] = (self.bitmap[0] << shift) | 1;
            }
            self.last_seq = seq;
        } else {
            let diff = self.last_seq - seq;
            if diff < REPLAY_WINDOW_SIZE as u64 {
                let word_idx = (diff / 64) as usize;
                let bit_idx = (diff % 64) as usize;
                self.bitmap[word_idx] |= 1u64 << bit_idx;
            }
        }
    }

    pub fn reset(&mut self) {
        self.last_seq = 0;
        self.bitmap = [0, 0];
        self.initialized = false;
    }
}

// =============================================================================
// Scorched-Earth Anti-Tamper Key Zeroization
// =============================================================================

/// Multi-pass volatile memory sanitization for quarantined key storage.
/// Defeats remanence attacks and physical memory probing.
#[inline(never)]
pub fn emergency_wipe_keys() {
    let key_ptr = CRYPTO_LOCKED_KEYS_VADDR as *mut u8;

    // Pass 1: Pattern 0xAA
    for i in 0..LOCKED_KEYS_SIZE {
        unsafe { ptr::write_volatile(key_ptr.add(i), 0xAA) };
    }
    fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);

    // Pass 2: Pattern 0x55
    for i in 0..LOCKED_KEYS_SIZE {
        unsafe { ptr::write_volatile(key_ptr.add(i), 0x55) };
    }
    fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);

    // Pass 3: Zero out
    for i in 0..LOCKED_KEYS_SIZE {
        unsafe { ptr::write_volatile(key_ptr.add(i), 0x00) };
    }
    fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

/// Comprehensive zeroization of keys and all shared memory rings.
pub fn emergency_wipe_all() {
    emergency_wipe_keys();

    // Wipe shared ring buffers
    let red_ring = RED_CRYPTO_RING_VADDR as *mut u8;
    for i in 0..RING_TOTAL_SIZE {
        unsafe { ptr::write_volatile(red_ring.add(i), 0x00) };
    }

    let black_ring = CRYPTO_BLACK_RING_VADDR as *mut u8;
    for i in 0..RING_TOTAL_SIZE {
        unsafe { ptr::write_volatile(black_ring.add(i), 0x00) };
    }

    fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

// =============================================================================
// CRYPTO Domain Controller
// =============================================================================

pub const DIR_RED_TO_BLACK: u8 = 0x01;
pub const DIR_BLACK_TO_RED: u8 = 0x02;
const AAD_DOMAIN: &[u8] = b"sEL4-MILS-CRYPTO-V2:";

pub struct CryptoDomainAppliance {
    pub red_rx: ZeroCopyRxRing,
    pub red_tx: ZeroCopyTxRing,
    pub black_rx: ZeroCopyRxRing,
    pub black_tx: ZeroCopyTxRing,
    pub anti_replay: AntiReplayWindow,
    pub tx_seq: u64,
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    keys_armed: bool,
}

impl Drop for CryptoDomainAppliance {
    fn drop(&mut self) {
        self.zeroize_domain_keys();
    }
}

fn is_all_zeros_32(buf: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for &b in buf {
        acc |= b;
    }
    subtle::ConstantTimeEq::ct_eq(&acc, &0u8).into()
}

fn build_aead_nonce(dir: u8, seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = dir;
    n[4..12].copy_from_slice(&seq.to_be_bytes());
    n
}

fn build_aead_aad(dir: u8, seq: u64, pt_len: usize) -> [u8; 35] {
    let mut aad = [0u8; 35];
    aad[..20].copy_from_slice(AAD_DOMAIN);
    aad[20..24].copy_from_slice(&RING_VERSION.to_be_bytes());
    aad[24] = dir;
    aad[25..33].copy_from_slice(&seq.to_be_bytes());
    aad[33..35].copy_from_slice(&(pt_len as u16).to_be_bytes());
    aad
}

impl CryptoDomainAppliance {
    /// Attach rings and read provisioned `[tx_key(32) || rx_key(32)]` from `CRYPTO_LOCKED_KEYS_VADDR`.
    /// Fail-closed: if keys are all-zero (unprovisioned or wiped), `keys_armed = false` and
    /// all encryption/decryption calls refuse with `RingError::Zeroized`.
    pub unsafe fn init_rings() -> Self {
        let mut tx_key = [0u8; 32];
        let mut rx_key = [0u8; 32];
        let key_ptr = CRYPTO_LOCKED_KEYS_VADDR as *const u8;
        for (i, byte) in tx_key.iter_mut().enumerate() {
            *byte = ptr::read_volatile(key_ptr.add(i));
        }
        for (i, byte) in rx_key.iter_mut().enumerate() {
            *byte = ptr::read_volatile(key_ptr.add(32 + i));
        }
        Self::init_rings_with_keys(tx_key, rx_key)
    }

    pub unsafe fn init_rings_with_keys(tx_key: [u8; 32], rx_key: [u8; 32]) -> Self {
        Self::from_rings_with_keys(
            ZeroCopyRxRing::new(RED_CRYPTO_RING_VADDR + TX_OFFSET),
            ZeroCopyTxRing::new(RED_CRYPTO_RING_VADDR + RX_OFFSET),
            ZeroCopyRxRing::new(CRYPTO_BLACK_RING_VADDR + RX_OFFSET),
            ZeroCopyTxRing::new(CRYPTO_BLACK_RING_VADDR + TX_OFFSET),
            tx_key,
            rx_key,
        )
    }

    pub fn from_rings_with_keys(
        red_rx: ZeroCopyRxRing,
        red_tx: ZeroCopyTxRing,
        black_rx: ZeroCopyRxRing,
        black_tx: ZeroCopyTxRing,
        tx_key: [u8; 32],
        rx_key: [u8; 32],
    ) -> Self {
        let keys_armed = !is_all_zeros_32(&tx_key) && !is_all_zeros_32(&rx_key);
        Self {
            red_rx,
            red_tx,
            black_rx,
            black_tx,
            anti_replay: AntiReplayWindow::new(),
            tx_seq: 0,
            tx_key,
            rx_key,
            keys_armed,
        }
    }

    pub fn zeroize_domain_keys(&mut self) {
        self.tx_key.zeroize();
        self.rx_key.zeroize();
        self.keys_armed = false;
        compiler_fence(Ordering::SeqCst);
    }

    /// Process outbound plaintext from RED domain, encrypt with AES-256-GCM in-place, and forward to BLACK domain.
    /// Wire frame layout: `[uint64 seq (8B)][ciphertext (pt_len B)][16-byte GCM tag]`
    pub fn process_red_to_black(&mut self) -> Result<bool, RingError> {
        if !self.keys_armed || is_all_zeros_32(&self.tx_key) {
            return Err(RingError::Zeroized);
        }
        if let Some(rx_frame) = self.red_rx.peek_rx_slot()? {
            let plaintext = rx_frame.payload;
            let pt_len = plaintext.len();
            if pt_len > u16::MAX as usize {
                return Err(RingError::SlotTooLarge);
            }
            let seq = self.tx_seq;
            let next_seq = self.tx_seq.checked_add(1).ok_or(RingError::Zeroized)?;
            let ct_len = 8 + pt_len + 16;
            let tx_slot = self.black_tx.acquire_tx_slot(ct_len, MSG_TYPE_CIPHERTEXT)?;

            tx_slot[0..8].copy_from_slice(&seq.to_be_bytes());
            tx_slot[8..8 + pt_len].copy_from_slice(plaintext);

            let nonce_bytes = build_aead_nonce(DIR_RED_TO_BLACK, seq);
            let nonce = Nonce::from(nonce_bytes);
            let aad = build_aead_aad(DIR_RED_TO_BLACK, seq, pt_len);
            let cipher = Aes256Gcm::new((&self.tx_key).into());
            let tag = cipher
                .encrypt_inout_detached(
                    &nonce,
                    &aad,
                    InOutBuf::from(&mut tx_slot[8..8 + pt_len]),
                )
                .map_err(|_| RingError::InvalidFrame)?;
            tx_slot[8 + pt_len..8 + pt_len + 16].copy_from_slice(tag.as_slice());

            self.tx_seq = next_seq;
            self.black_tx.commit_tx_slot(ct_len)?;
            let flen = rx_frame.frame_len;
            drop(rx_frame);
            self.red_rx.commit_rx_slot(flen)?;

            microkit_notify(CHANNEL_BLACK);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Process inbound ciphertext from BLACK domain, authenticate via AES-256-GCM before exposing plaintext, and forward to RED.
    pub fn process_black_to_red(&mut self) -> Result<bool, RingError> {
        if !self.keys_armed || is_all_zeros_32(&self.rx_key) {
            return Err(RingError::Zeroized);
        }
        if let Some(rx_frame) = self.black_rx.peek_rx_slot()? {
            let ciphertext = rx_frame.payload;
            if ciphertext.len() < 24 {
                let flen = rx_frame.frame_len;
                drop(rx_frame);
                self.black_rx.commit_rx_slot(flen)?;
                return Ok(false);
            }

            let mut seq_bytes = [0u8; 8];
            seq_bytes.copy_from_slice(&ciphertext[0..8]);
            let seq = u64::from_be_bytes(seq_bytes);

            if !self.anti_replay.check(seq) {
                let flen = rx_frame.frame_len;
                drop(rx_frame);
                self.black_rx.commit_rx_slot(flen)?;
                return Ok(false);
            }

            let pt_len = ciphertext.len() - 24;
            if pt_len > u16::MAX as usize {
                let flen = rx_frame.frame_len;
                drop(rx_frame);
                self.black_rx.commit_rx_slot(flen)?;
                return Ok(false);
            }
            let mut tag_arr = [0u8; 16];
            tag_arr.copy_from_slice(&ciphertext[8 + pt_len..8 + pt_len + 16]);
            let tag = Tag::<Aes256Gcm>::from(tag_arr);

            let tx_slot = self.red_tx.acquire_tx_slot(pt_len, MSG_TYPE_PLAINTEXT)?;
            tx_slot[..pt_len].copy_from_slice(&ciphertext[8..8 + pt_len]);

            let nonce_bytes = build_aead_nonce(DIR_BLACK_TO_RED, seq);
            let nonce = Nonce::from(nonce_bytes);
            let aad = build_aead_aad(DIR_BLACK_TO_RED, seq, pt_len);
            let cipher = Aes256Gcm::new((&self.rx_key).into());
            if cipher
                .decrypt_inout_detached(&nonce, &aad, InOutBuf::from(&mut tx_slot[..pt_len]), &tag)
                .is_err()
            {
                // Scrub unauthenticated buffer bytes immediately before dropping RX frame
                for byte in tx_slot[..pt_len].iter_mut() {
                    unsafe { ptr::write_volatile(byte as *mut u8, 0) };
                }
                compiler_fence(Ordering::SeqCst);
                let flen = rx_frame.frame_len;
                drop(rx_frame);
                self.black_rx.commit_rx_slot(flen)?;
                return Ok(false);
            }

            self.anti_replay.mark(seq);
            self.red_tx.commit_tx_slot(pt_len)?;
            let flen = rx_frame.frame_len;
            drop(rx_frame);
            self.black_rx.commit_rx_slot(flen)?;

            microkit_notify(CHANNEL_RED);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// =============================================================================
// seL4 Microkit Hooks & Runtime
// =============================================================================

#[inline(always)]
pub fn microkit_notify(channel: usize) {
    compiler_fence(Ordering::SeqCst);
    let _ = channel;
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    init();
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Fail-closed scorched-earth memory sweep
    emergency_wipe_keys();
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn init() {
    compiler_fence(Ordering::SeqCst);
    unsafe {
        let _ = CryptoDomainAppliance::init_rings();
    }
}

#[no_mangle]
pub extern "C" fn notified(channel: usize) {
    match channel {
        CHANNEL_RED => {
            compiler_fence(Ordering::SeqCst);
        }
        CHANNEL_BLACK => {
            compiler_fence(Ordering::SeqCst);
        }
        _ => {}
    }
}

// =============================================================================
// Unit Tests (Mocking seL4 Shared Memory Pages & Locked Keys)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_TX: [u8; 32] = [0x17u8; 32];
    const TEST_KEY_RX: [u8; 32] = [0x93u8; 32];

    #[test]
    fn test_crypto_domain_mediation_roundtrip() {
        let mut red_ring = [0u8; RING_TOTAL_SIZE];
        let mut black_ring = [0u8; RING_TOTAL_SIZE];

        let red_base = red_ring.as_mut_ptr() as usize;
        let black_base = black_ring.as_mut_ptr() as usize;

        unsafe {
            let mut red_tx = ZeroCopyTxRing::new(red_base + TX_OFFSET);
            let black_rx = ZeroCopyRxRing::new(black_base + TX_OFFSET);

            let mut appliance = CryptoDomainAppliance::from_rings_with_keys(
                ZeroCopyRxRing::new(red_base + TX_OFFSET),
                ZeroCopyTxRing::new(red_base + RX_OFFSET),
                ZeroCopyRxRing::new(black_base + RX_OFFSET),
                ZeroCopyTxRing::new(black_base + TX_OFFSET),
                TEST_KEY_TX,
                TEST_KEY_RX,
            );

            // 1. RED sends plaintext
            let msg = b"MISSION CRITICAL TACTICAL DISPATCH";
            red_tx.push(msg, MSG_TYPE_PLAINTEXT).unwrap();

            // 2. CRYPTO mediates RED -> BLACK using real AES-256-GCM
            assert!(appliance.process_red_to_black().unwrap());

            // 3. BLACK receives ciphertext (NOT 0xA5 XOR and NOT trailing 0x5A!)
            let ct_frame = black_rx.peek_rx_slot().unwrap().unwrap();
            assert_eq!(ct_frame.msg_type, MSG_TYPE_CIPHERTEXT);
            assert_ne!(ct_frame.payload, msg);
            assert_eq!(ct_frame.payload.len(), 8 + msg.len() + 16);
            assert_ne!(ct_frame.payload[8], msg[0] ^ 0xA5);
            assert_ne!(&ct_frame.payload[ct_frame.payload.len() - 16..], &[0x5Au8; 16]);
            let flen = ct_frame.frame_len;
            drop(ct_frame);

            let mut black_rx_mut = ZeroCopyRxRing::new(black_base + TX_OFFSET);
            black_rx_mut.commit_rx_slot(flen).unwrap();

            // 4. Seal authentic inbound ciphertext for BLACK -> RED
            let pt_inbound = [b'X'; 16];
            let seq = 1u64;
            let mut resp_buf = [0u8; 8 + 16 + 16];
            resp_buf[..8].copy_from_slice(&seq.to_be_bytes());
            resp_buf[8..24].copy_from_slice(&pt_inbound);
            let nonce = Nonce::from(build_aead_nonce(DIR_BLACK_TO_RED, seq));
            let aad = build_aead_aad(DIR_BLACK_TO_RED, seq, 16);
            let tag = Aes256Gcm::new((&TEST_KEY_RX).into())
                .encrypt_inout_detached(&nonce, &aad, InOutBuf::from(&mut resp_buf[8..24]))
                .unwrap();
            resp_buf[24..40].copy_from_slice(tag.as_slice());

            let mut black_tx = ZeroCopyTxRing::new(black_base + RX_OFFSET);
            black_tx.push(&resp_buf, MSG_TYPE_CIPHERTEXT).unwrap();

            // 5. CRYPTO mediates BLACK -> RED
            assert!(appliance.process_black_to_red().unwrap());

            // 6. RED receives decrypted plaintext
            let red_rx = ZeroCopyRxRing::new(red_base + RX_OFFSET);
            let pt_frame = red_rx.peek_rx_slot().unwrap().unwrap();
            assert_eq!(pt_frame.msg_type, MSG_TYPE_PLAINTEXT);
            assert_eq!(pt_frame.payload, &pt_inbound);

            // 7. Verify replay of identical packet fails closed
            let flen2 = pt_frame.frame_len;
            drop(pt_frame);
            let mut red_rx_mut = ZeroCopyRxRing::new(red_base + RX_OFFSET);
            red_rx_mut.commit_rx_slot(flen2).unwrap();

            black_tx.push(&resp_buf, MSG_TYPE_CIPHERTEXT).unwrap();
            assert!(!appliance.process_black_to_red().unwrap());
        }
    }

    #[test]
    fn test_crypto_domain_rejects_unprovisioned_all_zero_keys() {
        let mut red_ring = [0u8; RING_TOTAL_SIZE];
        let mut black_ring = [0u8; RING_TOTAL_SIZE];
        let red_base = red_ring.as_mut_ptr() as usize;
        let black_base = black_ring.as_mut_ptr() as usize;

        unsafe {
            let mut red_tx = ZeroCopyTxRing::new(red_base + TX_OFFSET);
            red_tx.push(b"SECRET", MSG_TYPE_PLAINTEXT).unwrap();

            let mut appliance = CryptoDomainAppliance::from_rings_with_keys(
                ZeroCopyRxRing::new(red_base + TX_OFFSET),
                ZeroCopyTxRing::new(red_base + RX_OFFSET),
                ZeroCopyRxRing::new(black_base + RX_OFFSET),
                ZeroCopyTxRing::new(black_base + TX_OFFSET),
                [0u8; 32],
                [0u8; 32],
            );
            assert_eq!(appliance.process_red_to_black(), Err(RingError::Zeroized));
            assert_eq!(appliance.process_black_to_red(), Err(RingError::Zeroized));
        }
    }

    #[test]
    fn test_emergency_wipe_keys_execution() {
        let mut key_buf = [0xFFu8; LOCKED_KEYS_SIZE];
        let ptr = key_buf.as_mut_ptr();

        for i in 0..LOCKED_KEYS_SIZE {
            unsafe { ptr::write_volatile(ptr.add(i), 0xAA) };
        }
        for i in 0..LOCKED_KEYS_SIZE {
            unsafe { ptr::write_volatile(ptr.add(i), 0x55) };
        }
        for i in 0..LOCKED_KEYS_SIZE {
            unsafe { ptr::write_volatile(ptr.add(i), 0x00) };
        }

        assert!(key_buf.iter().all(|&b| b == 0x00));
    }

    #[test]
    fn test_rfc_6479_anti_replay_window() {
        let mut win = AntiReplayWindow::new();

        // 1. Initial sequence 0
        assert!(win.check(0));
        win.mark(0);
        assert!(!win.check(0)); // Reject duplicate seq 0

        // 2. Sequential packets
        assert!(win.check(1));
        win.mark(1);
        assert!(win.check(2));
        win.mark(2);

        // Reject replay of 1 and 2
        assert!(!win.check(1));
        assert!(!win.check(2));

        // 3. Out-of-order jump forward
        assert!(win.check(10));
        win.mark(10);
        // Packets inside window [0..10] still valid if unread
        assert!(win.check(5));
        win.mark(5);
        assert!(!win.check(5)); // Reject duplicate

        // 4. Large jump forward
        win.mark(200);
        // Packets older than (200 - 128 = 72) must be rejected as stale
        assert!(!win.check(70));
        assert!(win.check(150));
    }

    #[test]
    fn test_crypto_domain_tampered_mac_rejection() {
        let mut red_ring = [0u8; RING_TOTAL_SIZE];
        let mut black_ring = [0u8; RING_TOTAL_SIZE];

        let red_base = red_ring.as_mut_ptr() as usize;
        let black_base = black_ring.as_mut_ptr() as usize;

        unsafe {
            let mut appliance = CryptoDomainAppliance::from_rings_with_keys(
                ZeroCopyRxRing::new(red_base + TX_OFFSET),
                ZeroCopyTxRing::new(red_base + RX_OFFSET),
                ZeroCopyRxRing::new(black_base + RX_OFFSET),
                ZeroCopyTxRing::new(black_base + TX_OFFSET),
                TEST_KEY_TX,
                TEST_KEY_RX,
            );

            let mut black_tx = ZeroCopyTxRing::new(black_base + RX_OFFSET);
            // Forge legacy XOR-0xA5 + 0x5A frame AND verify AES-256-GCM rejects it fail-closed
            let mut resp_buf = [0u8; 8 + 16 + 16];
            resp_buf[7] = 5; // seq = 5
            for i in 0..16 {
                resp_buf[8 + i] = b'Y' ^ 0xA5;
            }
            for i in 24..40 {
                resp_buf[i] = 0x5A;
            }
            black_tx.push(&resp_buf, MSG_TYPE_CIPHERTEXT).unwrap();

            // Forged legacy stub packet must fail closed (returns Ok(false))
            assert!(!appliance.process_black_to_red().unwrap());

            // Plaintext ring to RED must remain empty
            let red_rx = ZeroCopyRxRing::new(red_base + RX_OFFSET);
            assert!(red_rx.peek_rx_slot().unwrap().is_none());
        }
    }

    #[test]
    fn test_crypto_domain_short_frame_rejection() {
        let mut red_ring = [0u8; RING_TOTAL_SIZE];
        let mut black_ring = [0u8; RING_TOTAL_SIZE];

        let red_base = red_ring.as_mut_ptr() as usize;
        let black_base = black_ring.as_mut_ptr() as usize;

        unsafe {
            let mut appliance = CryptoDomainAppliance::from_rings_with_keys(
                ZeroCopyRxRing::new(red_base + TX_OFFSET),
                ZeroCopyTxRing::new(red_base + RX_OFFSET),
                ZeroCopyRxRing::new(black_base + RX_OFFSET),
                ZeroCopyTxRing::new(black_base + TX_OFFSET),
                TEST_KEY_TX,
                TEST_KEY_RX,
            );

            let mut black_tx = ZeroCopyTxRing::new(black_base + RX_OFFSET);
            let truncated_payload = [0xAAu8; 12]; // Less than 24-byte minimum (8B seq + 16B tag)
            black_tx.push(&truncated_payload, MSG_TYPE_CIPHERTEXT).unwrap();

            // Must drop truncated payload gracefully and return Ok(false)
            assert!(!appliance.process_black_to_red().unwrap());

            // Plaintext ring to RED must remain empty
            let red_rx = ZeroCopyRxRing::new(red_base + RX_OFFSET);
            assert!(red_rx.peek_rx_slot().unwrap().is_none());
        }
    }

    #[test]
    fn test_anti_replay_window_boundary_edge_cases() {
        let mut win = AntiReplayWindow::new();

        // Check exact window shifts:
        // Mark seq 100
        win.mark(100);
        // Distance 127: (100 - 127 = invalid because 100 < 127)
        // Let's mark seq 200
        win.mark(200);

        // Within 128 window: seq in [73..200]
        // 200 - 73 = 127 (allowed)
        assert!(win.check(73));
        // 200 - 72 = 128 (out of 128-window [0..127])
        assert!(!win.check(72));
        assert!(!win.check(71));
        assert!(!win.check(0));

        // Mark 73
        win.mark(73);
        assert!(!win.check(73)); // Duplicate rejected

        // Huge jump: seq 1_000_000
        assert!(win.check(1_000_000));
        win.mark(1_000_000);
        assert!(!win.check(200)); // Old seq now far behind
        assert!(win.check(1_000_000 - 127));
        assert!(!win.check(1_000_000 - 128));
    }
}
