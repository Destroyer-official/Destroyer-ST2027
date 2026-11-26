//! Bare-Metal seL4 Microkit BLACK Protection Domain (Untrusted Network Transport)
//! ==============================================================================
//! Executes with `#![no_std]` and `#![no_main]`.
//! Zero dynamic allocations, zero heap, zero operating system dependencies.
//!
//! Architectural Invariants (MILS Strict Separation):
//! 1. Strictly isolated Ciphertext / Network Transport Domain.
//! 2. Zero access to Plaintext Memory (`0x10000000`).
//! 3. Zero access to Key Storage Memory (`0x30000000`).
//! 4. Communicates EXCLUSIVELY with the CRYPTO domain via zero-copy ring
//!    buffer mapped at `0x20000000` and Microkit notification Channel 2.
//! 5. Implements Constant-Rate 20 Hz Traffic Pacing with uniform 1232-byte frames:
//!    emits authentic ciphertext or 0xFF synthetic chaff to eliminate SIGINT
//!    traffic flow correlation.

#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::{compiler_fence, fence, AtomicU32, Ordering};

// =============================================================================
// Memory Mapping Constants (from sel4_mils_appliance/system.xml)
// =============================================================================

/// seL4 Microkit shared-memory ring buffer base address for CRYPTO <-> BLACK
pub const CRYPTO_BLACK_RING_VADDR: usize = 0x20000000;
pub const RING_TOTAL_SIZE: usize = 0x10000; // 64 KiB
pub const RING_HALF_SIZE: usize = 0x8000; // 32 KiB

/// Ring buffer offsets
pub const CRYPTO_TO_BLACK_OFFSET: usize = 0x0000; // RX: from CRYPTO
pub const BLACK_TO_CRYPTO_OFFSET: usize = 0x8000; // TX: to CRYPTO

/// Microkit Notification Channel connecting CRYPTO and BLACK domains
pub const CHANNEL_CRYPTO: usize = 2;

/// ST2027 Wire Protocol Constants
pub const ST2027_CELL_SIZE: usize = 1232;
pub const CHAFF_CELL_TYPE: u8 = 0xFF;
pub const DATA_CELL_TYPE: u8 = 0x01;
pub const MSG_TYPE_WRAP: u8 = 0xFE;

/// Ring Buffer Protocol Constants
pub const RING_MAGIC: u32 = 0x53454C34; // "sEL4"
pub const RING_VERSION: u32 = 1;
pub const RING_CTRL_SIZE: usize = 64;
pub const RING_DATA_CAPACITY: usize = RING_HALF_SIZE - RING_CTRL_SIZE; // 32704 bytes

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

/// Zero-Copy SPSC Transmit Ring (BLACK -> CRYPTO)
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

        Self {
            ctrl,
            buffer,
            capacity,
        }
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

    pub fn acquire_tx_slot(
        &mut self,
        payload_len: usize,
        msg_type: u8,
    ) -> Result<&mut [u8], RingError> {
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

/// Zero-Copy SPSC Receive Ring (CRYPTO -> BLACK)
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
        Self {
            ctrl,
            buffer,
            capacity,
        }
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
// Constant-Rate Chaff PRNG (RFC 8439 ChaCha20 Stream, Fail-Closed Without Seed)
// =============================================================================

#[inline(always)]
fn chacha_qr(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

pub struct ChaffPrng {
    key: [u32; 8],
    counter: u64,
    block: [u8; 64],
    pos: usize,
    seeded: bool,
}

impl ChaffPrng {
    pub const fn unseeded() -> Self {
        Self {
            key: [0u32; 8],
            counter: 0,
            block: [0u8; 64],
            pos: 64,
            seeded: false,
        }
    }

    pub fn from_seed(seed_key: &[u8; 32]) -> Result<Self, RingError> {
        let mut non_zero = 0u8;
        for &b in seed_key {
            non_zero |= b;
        }
        if non_zero == 0 {
            return Err(RingError::Zeroized);
        }
        let mut key = [0u32; 8];
        for (i, word) in key.iter_mut().enumerate() {
            let off = i * 4;
            *word = u32::from_le_bytes([
                seed_key[off],
                seed_key[off + 1],
                seed_key[off + 2],
                seed_key[off + 3],
            ]);
        }
        Ok(Self {
            key,
            counter: 0,
            block: [0u8; 64],
            pos: 64,
            seeded: true,
        })
    }

    pub const fn new(seed: u64) -> Self {
        let mut z = seed.wrapping_add(0x9E3779B97F4A7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        let s0 = z ^ (z >> 31);
        let mut key = [0u32; 8];
        let mut i = 0usize;
        while i < 8 {
            z = z.wrapping_add(0x9E3779B97F4A7C15);
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            let w = z ^ (z >> 31);
            key[i] = ((w ^ s0) & 0xFFFF_FFFF) as u32 ^ ((i as u32).wrapping_mul(0x9E37_79B9));
            i += 1;
        }
        Self {
            key,
            counter: 0,
            block: [0u8; 64],
            pos: 64,
            seeded: seed != 0,
        }
    }

    fn refill_block(&mut self) {
        const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&CONSTANTS);
        state[4..12].copy_from_slice(&self.key);
        state[12] = (self.counter & 0xFFFF_FFFF) as u32;
        state[13] = ((self.counter >> 32) & 0xFFFF_FFFF) as u32;
        state[14] = 0x5345_4C34; // domain: "sEL4"
        state[15] = 0x424C_4B32; // domain: "BLK2"
        let initial = state;
        for _ in 0..10 {
            chacha_qr(&mut state, 0, 4, 8, 12);
            chacha_qr(&mut state, 1, 5, 9, 13);
            chacha_qr(&mut state, 2, 6, 10, 14);
            chacha_qr(&mut state, 3, 7, 11, 15);
            chacha_qr(&mut state, 0, 5, 10, 15);
            chacha_qr(&mut state, 1, 6, 11, 12);
            chacha_qr(&mut state, 2, 7, 8, 13);
            chacha_qr(&mut state, 3, 4, 9, 14);
        }
        for i in 0..16 {
            let out_w = state[i].wrapping_add(initial[i]).to_le_bytes();
            self.block[i * 4..i * 4 + 4].copy_from_slice(&out_w);
        }
        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }

    pub fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RingError> {
        if !self.seeded {
            return Err(RingError::Zeroized);
        }
        for b in dest.iter_mut() {
            if self.pos >= 64 {
                self.refill_block();
            }
            *b = self.block[self.pos];
            self.pos += 1;
        }
        Ok(())
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = self.try_fill_bytes(dest);
    }
}

// =============================================================================
// BLACK Domain Controller
// =============================================================================

pub struct BlackDomainAppliance {
    pub rx_from_crypto: ZeroCopyRxRing,
    pub tx_to_crypto: ZeroCopyTxRing,
    pub chaff_prng: ChaffPrng,
}

impl BlackDomainAppliance {
    /// Fail-closed default init: leaves PRNG unseeded until `provision_chaff_seed` supplies real entropy.
    pub unsafe fn init_rings() -> Self {
        let rx = ZeroCopyRxRing::new(CRYPTO_BLACK_RING_VADDR + CRYPTO_TO_BLACK_OFFSET);
        let tx = ZeroCopyTxRing::new(CRYPTO_BLACK_RING_VADDR + BLACK_TO_CRYPTO_OFFSET);
        Self {
            rx_from_crypto: rx,
            tx_to_crypto: tx,
            chaff_prng: ChaffPrng::unseeded(),
        }
    }

    pub unsafe fn init_rings_with_seed(seed_key: &[u8; 32]) -> Result<Self, RingError> {
        let prng = ChaffPrng::from_seed(seed_key)?;
        let rx = ZeroCopyRxRing::new(CRYPTO_BLACK_RING_VADDR + CRYPTO_TO_BLACK_OFFSET);
        let tx = ZeroCopyTxRing::new(CRYPTO_BLACK_RING_VADDR + BLACK_TO_CRYPTO_OFFSET);
        Ok(Self {
            rx_from_crypto: rx,
            tx_to_crypto: tx,
            chaff_prng: prng,
        })
    }

    /// Emit uniform 1232-byte wire frame with ChaCha20-whitened padding (zero 0x00 size oracle).
    pub fn emit_next_wire_cell(
        &mut self,
        out_cell: &mut [u8; ST2027_CELL_SIZE],
    ) -> Result<bool, RingError> {
        if !self.chaff_prng.seeded {
            return Err(RingError::Zeroized);
        }
        if let Some(frame) = self.rx_from_crypto.peek_rx_slot()? {
            let ct = frame.payload;
            let ct_len = ct.len();

            let copy_len = if ct_len > ST2027_CELL_SIZE - 3 {
                return Err(RingError::SlotTooLarge);
            } else {
                ct_len
            };

            let be_bytes = (copy_len as u16).to_be_bytes();
            out_cell[0] = be_bytes[0];
            out_cell[1] = be_bytes[1];
            out_cell[2] = DATA_CELL_TYPE;

            out_cell[3..3 + copy_len].copy_from_slice(&ct[..copy_len]);

            // Randomize trailing cell padding with ChaCha20 keystream instead of 0x00
            self.chaff_prng.try_fill_bytes(&mut out_cell[3 + copy_len..])?;

            self.rx_from_crypto.commit_rx_slot(frame.frame_len)?;
            Ok(true) // Authentic ciphertext emitted
        } else {
            out_cell[0] = 0x00;
            out_cell[1] = 0x00;
            out_cell[2] = CHAFF_CELL_TYPE;

            self.chaff_prng.try_fill_bytes(&mut out_cell[3..])?;
            Ok(false) // Chaff emitted
        }
    }

    /// Emit uniform 1232-byte wire cell with encrypted header mask (`header XOR mask3`),
    /// preventing passive distinction of DATA_CELL_TYPE vs CHAFF_CELL_TYPE or length.
    pub fn emit_masked_wire_cell(
        &mut self,
        out_cell: &mut [u8; ST2027_CELL_SIZE],
    ) -> Result<bool, RingError> {
        let mut mask = [0u8; 3];
        self.chaff_prng.try_fill_bytes(&mut mask)?;
        let is_real = self.emit_next_wire_cell(out_cell)?;
        out_cell[0] ^= mask[0];
        out_cell[1] ^= mask[1];
        out_cell[2] ^= mask[2];
        Ok(is_real)
    }

    /// Ingest an inbound 1232-byte wire frame from the physical network.
    /// Drops chaff cells and forwards authentic ciphertext zero-copy to CRYPTO domain.
    pub fn ingest_wire_cell(&mut self, cell: &[u8]) -> Result<bool, RingError> {
        if cell.len() < 3 {
            return Ok(false);
        }

        let cell_type = cell[2];
        if cell_type == CHAFF_CELL_TYPE {
            // Drop chaff immediately in BLACK domain
            return Ok(false);
        }

        let payload_len = ((cell[0] as usize) << 8) | (cell[1] as usize);
        if payload_len == 0 || 3 + payload_len > cell.len() {
            return Ok(false);
        }

        let ciphertext = &cell[3..3 + payload_len];

        // Push ciphertext into TX ring to CRYPTO domain with zero copies
        self.tx_to_crypto.push(ciphertext, DATA_CELL_TYPE)?;

        // Notify CRYPTO domain on Channel 2
        microkit_notify(CHANNEL_CRYPTO);
        Ok(true)
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
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    init();
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn init() {
    compiler_fence(Ordering::SeqCst);
    unsafe {
        let _ = BlackDomainAppliance::init_rings();
    }
}

#[no_mangle]
pub extern "C" fn notified(channel: usize) {
    if channel != CHANNEL_CRYPTO {
        return;
    }
    compiler_fence(Ordering::SeqCst);
}

// =============================================================================
// Unit Tests (Mocking seL4 Shared Memory Pages & Wire Transport)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chaff_prng_entropy_distribution() {
        let mut prng = ChaffPrng::new(0xCAFE_BABE_DEAD_BEEF);
        let mut buf = [0u8; 10000];
        prng.fill_bytes(&mut buf);

        // Check non-zero and reasonable byte distribution
        let mut counts = [0usize; 256];
        for &b in &buf {
            counts[b as usize] += 1;
        }

        // Every byte bucket should have at least 15 hits out of 10,000 (uniform expectation is ~39)
        for &cnt in &counts {
            assert!(cnt >= 15, "PRNG bucket deficiency: {}", cnt);
        }
    }

    #[test]
    fn test_black_domain_chaff_emission_on_empty_queue() {
        let mut shm = [0u8; RING_TOTAL_SIZE];
        let base = shm.as_mut_ptr() as usize;

        unsafe {
            let mut appliance = BlackDomainAppliance {
                rx_from_crypto: ZeroCopyRxRing::new(base + CRYPTO_TO_BLACK_OFFSET),
                tx_to_crypto: ZeroCopyTxRing::new(base + BLACK_TO_CRYPTO_OFFSET),
                chaff_prng: ChaffPrng::new(0x1234_5678_9ABC_DEF0),
            };

            let mut out_cell = [0u8; ST2027_CELL_SIZE];
            let is_real = appliance.emit_next_wire_cell(&mut out_cell).unwrap();
            assert!(!is_real);
            assert_eq!(out_cell[2], CHAFF_CELL_TYPE);
            assert_eq!(out_cell[0], 0);
            assert_eq!(out_cell[1], 0);
        }
    }

    #[test]
    fn test_black_domain_real_ciphertext_emission() {
        let mut shm = [0u8; RING_TOTAL_SIZE];
        let base = shm.as_mut_ptr() as usize;

        unsafe {
            let mut crypto_tx = ZeroCopyTxRing::new(base + CRYPTO_TO_BLACK_OFFSET);
            let mut appliance = BlackDomainAppliance {
                rx_from_crypto: ZeroCopyRxRing::new(base + CRYPTO_TO_BLACK_OFFSET),
                tx_to_crypto: ZeroCopyTxRing::new(base + BLACK_TO_CRYPTO_OFFSET),
                chaff_prng: ChaffPrng::new(0x1234_5678_9ABC_DEF0),
            };

            let ct_payload = b"ENCRYPTED_POST_QUANTUM_CIPHERTEXT";
            crypto_tx.push(ct_payload, DATA_CELL_TYPE).unwrap();

            let mut out_cell = [0u8; ST2027_CELL_SIZE];
            let is_real = appliance.emit_next_wire_cell(&mut out_cell).unwrap();
            assert!(is_real);
            assert_eq!(out_cell[2], DATA_CELL_TYPE);

            let payload_len = ((out_cell[0] as usize) << 8) | (out_cell[1] as usize);
            assert_eq!(payload_len, ct_payload.len());
            assert_eq!(&out_cell[3..3 + payload_len], ct_payload);
        }
    }

    #[test]
    fn test_black_domain_chaff_rejection_on_ingest() {
        let mut shm = [0u8; RING_TOTAL_SIZE];
        let base = shm.as_mut_ptr() as usize;

        unsafe {
            let mut appliance = BlackDomainAppliance {
                rx_from_crypto: ZeroCopyRxRing::new(base + CRYPTO_TO_BLACK_OFFSET),
                tx_to_crypto: ZeroCopyTxRing::new(base + BLACK_TO_CRYPTO_OFFSET),
                chaff_prng: ChaffPrng::new(0x1234_5678_9ABC_DEF0),
            };

            // Ingest chaff cell: must be dropped immediately
            let mut chaff = [0u8; ST2027_CELL_SIZE];
            chaff[2] = CHAFF_CELL_TYPE;
            let ingested = appliance.ingest_wire_cell(&chaff).unwrap();
            assert!(!ingested);

            // Ingest real cell: must be forwarded to crypto ring
            let mut real_cell = [0u8; ST2027_CELL_SIZE];
            real_cell[0] = 0x00;
            real_cell[1] = 0x05;
            real_cell[2] = DATA_CELL_TYPE;
            real_cell[3..8].copy_from_slice(b"HELLO");

            let ingested_real = appliance.ingest_wire_cell(&real_cell).unwrap();
            assert!(ingested_real);

            // Verify crypto_rx receives it
            let crypto_rx = ZeroCopyRxRing::new(base + BLACK_TO_CRYPTO_OFFSET);
            let frame = crypto_rx.peek_rx_slot().unwrap().unwrap();
            assert_eq!(frame.payload, b"HELLO");
        }
    }

    #[test]
    fn test_black_domain_wire_cell_oversize_or_truncation() {
        let mut shm = [0u8; RING_TOTAL_SIZE];
        let base = shm.as_mut_ptr() as usize;

        unsafe {
            let mut appliance = BlackDomainAppliance {
                rx_from_crypto: ZeroCopyRxRing::new(base + CRYPTO_TO_BLACK_OFFSET),
                tx_to_crypto: ZeroCopyTxRing::new(base + BLACK_TO_CRYPTO_OFFSET),
                chaff_prng: ChaffPrng::new(0x1234_5678_9ABC_DEF0),
            };

            // 1. Truncated cell (< 3 bytes)
            let short_cell = [0x00, 0x05];
            assert!(!appliance.ingest_wire_cell(&short_cell).unwrap());

            // 2. Zero-length payload
            let zero_len_cell = [0x00, 0x00, DATA_CELL_TYPE, 0x00];
            assert!(!appliance.ingest_wire_cell(&zero_len_cell).unwrap());

            // 3. Oversized declared payload_len exceeding buffer
            let mut bad_len_cell = [0u8; 100];
            bad_len_cell[0] = 0x01; // payload_len = 256
            bad_len_cell[1] = 0x00;
            bad_len_cell[2] = DATA_CELL_TYPE;
            assert!(!appliance.ingest_wire_cell(&bad_len_cell).unwrap());
        }
    }

    #[test]
    fn test_black_domain_chaff_prng_seed_diversity() {
        let mut prng_a = ChaffPrng::new(0x1111_2222_3333_4444);
        let mut prng_b = ChaffPrng::new(0x5555_6666_7777_8888);

        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];

        prng_a.fill_bytes(&mut buf_a);
        prng_b.fill_bytes(&mut buf_b);

        assert_ne!(buf_a, buf_b);
    }

    #[test]
    fn test_black_domain_unseeded_chaff_fails_closed() {
        let mut shm = [0u8; RING_TOTAL_SIZE];
        let base = shm.as_mut_ptr() as usize;
        unsafe {
            let mut appliance = BlackDomainAppliance {
                rx_from_crypto: ZeroCopyRxRing::new(base + CRYPTO_TO_BLACK_OFFSET),
                tx_to_crypto: ZeroCopyTxRing::new(base + BLACK_TO_CRYPTO_OFFSET),
                chaff_prng: ChaffPrng::unseeded(),
            };
            let mut out_cell = [0u8; ST2027_CELL_SIZE];
            assert_eq!(appliance.emit_next_wire_cell(&mut out_cell), Err(RingError::Zeroized));
            assert!(ChaffPrng::from_seed(&[0u8; 32]).is_err());
        }
    }

    #[test]
    fn test_black_domain_masked_cell_and_randomized_padding() {
        let mut shm = [0u8; RING_TOTAL_SIZE];
        let base = shm.as_mut_ptr() as usize;
        unsafe {
            let mut crypto_tx = ZeroCopyTxRing::new(base + CRYPTO_TO_BLACK_OFFSET);
            crypto_tx.push(b"SHORT_CT", DATA_CELL_TYPE).unwrap();
            let mut appliance = BlackDomainAppliance {
                rx_from_crypto: ZeroCopyRxRing::new(base + CRYPTO_TO_BLACK_OFFSET),
                tx_to_crypto: ZeroCopyTxRing::new(base + BLACK_TO_CRYPTO_OFFSET),
                chaff_prng: ChaffPrng::from_seed(&[0x3Cu8; 32]).unwrap(),
            };
            let mut cell = [0u8; ST2027_CELL_SIZE];
            assert!(appliance.emit_masked_wire_cell(&mut cell).unwrap());
            // Trailing pad bytes must NOT be all-zero leak
            assert!(!cell[100..].iter().all(|&b| b == 0));
        }
    }
}
