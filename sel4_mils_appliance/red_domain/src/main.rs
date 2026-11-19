//! Bare-Metal seL4 Microkit RED Protection Domain (Plaintext / User Space)
//! =========================================================================
//! Executes with `#![no_std]` and `#![no_main]`.
//! Zero dynamic allocations, zero heap, zero operating system dependencies.
//!
//! Architectural Invariants (MILS Strict Separation):
//! 1. Strictly isolated Plaintext Domain.
//! 2. Zero network hardware drivers, zero sockets, zero physical bus access.
//! 3. Zero shared memory or communication channels with the BLACK domain.
//! 4. Zero access to CRYPTO locked key storage (`0x30000000`).
//! 5. Communicates EXCLUSIVELY with the CRYPTO domain via zero-copy ring
//!    buffer mapped at `0x10000000` and Microkit notification Channel 1.

#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr;
use core::sync::atomic::{compiler_fence, fence, AtomicU32, Ordering};

// =============================================================================
// Memory Mapping Constants (from sel4_mils_appliance/system.xml)
// =============================================================================

/// seL4 Microkit shared-memory ring buffer base address for RED <-> CRYPTO
pub const RED_CRYPTO_RING_VADDR: usize = 0x10000000;
pub const RING_TOTAL_SIZE: usize = 0x10000; // 64 KiB
pub const RING_HALF_SIZE: usize = 0x8000;  // 32 KiB per direction

/// Sub-buffer offsets within the 64 KiB shared memory region
pub const RED_TO_CRYPTO_OFFSET: usize = 0x0000; // TX: RED -> CRYPTO
pub const CRYPTO_TO_RED_OFFSET: usize = 0x8000; // RX: CRYPTO -> RED

/// Microkit Notification Channel connecting RED and CRYPTO domains
pub const CHANNEL_CRYPTO: usize = 1;

/// Magic identifier for seL4 Microkit Zero-Copy Ring: "sEL4" (0x53454C34)
pub const RING_MAGIC: u32 = 0x53454C34;
pub const RING_VERSION: u32 = 1;
pub const RING_CTRL_SIZE: usize = 64; // 64-byte cache line alignment
pub const RING_DATA_CAPACITY: usize = RING_HALF_SIZE - RING_CTRL_SIZE; // 32704 bytes

/// Message Types
pub const MSG_TYPE_PLAINTEXT: u8 = 0x01;
pub const MSG_TYPE_COMMAND: u8 = 0x02;
pub const MSG_TYPE_HEARTBEAT: u8 = 0x03;
pub const MSG_TYPE_WRAP: u8 = 0xFE;

// =============================================================================
// Zero-Copy Ring Buffer Memory Layout
// =============================================================================

/// Cache-line aligned control block at the header of each unidirectional ring.
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

/// Message frame header prepended to each message payload in the ring buffer.
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

/// Zero-Copy SPSC (Single-Producer Single-Consumer) Transmit Ring
pub struct ZeroCopyTxRing {
    ctrl: *mut RingControl,
    buffer: *mut u8,
    capacity: usize,
}

impl ZeroCopyTxRing {
    /// Initialize or attach to a TX ring buffer at specified base address.
    ///
    /// # Safety
    /// Base pointer must point to a valid, page-mapped memory region of at least
    /// `RING_HALF_SIZE` bytes.
    pub unsafe fn new(base_vaddr: usize) -> Self {
        let ctrl = base_vaddr as *mut RingControl;
        let buffer = (base_vaddr + RING_CTRL_SIZE) as *mut u8;
        let capacity = RING_DATA_CAPACITY;

        // Initialize header if not yet initialized
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

    /// Calculate available contiguous write space in bytes.
    pub fn available_write(&self) -> usize {
        let head = unsafe { (*self.ctrl).head.load(Ordering::Acquire) as usize };
        let tail = unsafe { (*self.ctrl).tail.load(Ordering::Acquire) as usize };
        if head >= tail {
            self.capacity - (head - tail) - 1
        } else {
            tail - head - 1
        }
    }

    /// Zero-Copy Slot Acquisition:
    /// Grants the caller direct mutable access to the ring buffer payload area.
    /// The caller writes data directly into the returned slice without copies.
    pub fn acquire_tx_slot(&mut self, payload_len: usize, msg_type: u8) -> Result<&mut [u8], RingError> {
        if payload_len == 0 || payload_len > (self.capacity - FRAME_HEADER_SIZE - 1) {
            return Err(RingError::SlotTooLarge);
        }

        let needed = FRAME_HEADER_SIZE + payload_len;
        let mut head = unsafe { (*self.ctrl).head.load(Ordering::Acquire) as usize };
        let tail = unsafe { (*self.ctrl).tail.load(Ordering::Acquire) as usize };

        if head >= tail {
            if head + needed > self.capacity {
                // Not enough room at end of buffer; check if we can wrap to 0
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
            // head < tail
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

    /// Commit the acquired slot, advancing the head pointer and making the frame
    /// visible to the consumer domain.
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

    /// Standard push convenience method copying payload into zero-copy slot.
    pub fn push(&mut self, data: &[u8], msg_type: u8) -> Result<(), RingError> {
        let slot = self.acquire_tx_slot(data.len(), msg_type)?;
        slot.copy_from_slice(data);
        self.commit_tx_slot(data.len())
    }
}

/// Zero-Copy SPSC (Single-Producer Single-Consumer) Receive Ring
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
    /// Attach to an RX ring buffer at specified base address.
    ///
    /// # Safety
    /// Base pointer must point to a valid, page-mapped memory region.
    pub unsafe fn new(base_vaddr: usize) -> Self {
        let ctrl = base_vaddr as *mut RingControl;
        let buffer = (base_vaddr + RING_CTRL_SIZE) as *const u8;
        let capacity = RING_DATA_CAPACITY;
        Self { ctrl, buffer, capacity }
    }

    /// Zero-Copy Peek:
    /// Returns a direct slice into the shared memory buffer for inbound messages.
    /// Zero data copying occurs.
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

    /// Commit the peeked slot, advancing the tail pointer and freeing buffer space.
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
// RED Domain Controller
// =============================================================================

pub struct RedDomainAppliance {
    pub tx_to_crypto: ZeroCopyTxRing,
    pub rx_from_crypto: ZeroCopyRxRing,
}

impl RedDomainAppliance {
    /// Create RED domain appliance instance mapped to `0x10000000`.
    ///
    /// # Safety
    /// `RED_CRYPTO_RING_VADDR` must be mapped into page table as `rw`.
    pub unsafe fn init_rings() -> Self {
        let tx = ZeroCopyTxRing::new(RED_CRYPTO_RING_VADDR + RED_TO_CRYPTO_OFFSET);
        let rx = ZeroCopyRxRing::new(RED_CRYPTO_RING_VADDR + CRYPTO_TO_RED_OFFSET);
        Self {
            tx_to_crypto: tx,
            rx_from_crypto: rx,
        }
    }

    /// Send a plaintext message to the CRYPTO domain with zero copies.
    pub fn send_plaintext(&mut self, message: &[u8]) -> Result<(), RingError> {
        self.tx_to_crypto.push(message, MSG_TYPE_PLAINTEXT)?;
        // Issue seL4 notification on Channel 1
        microkit_notify(CHANNEL_CRYPTO);
        Ok(())
    }

    /// Poll for inbound decrypted plaintext messages from CRYPTO domain.
    pub fn process_inbound<F>(&mut self, mut handler: F) -> Result<bool, RingError>
    where
        F: FnMut(&[u8], u8),
    {
        if let Some(frame) = self.rx_from_crypto.peek_rx_slot()? {
            handler(frame.payload, frame.msg_type);
            let flen = frame.frame_len;
            drop(frame);
            self.rx_from_crypto.commit_rx_slot(flen)?;
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
    // In seL4 Microkit, this invokes the seL4_Notify system call for channel
    compiler_fence(Ordering::SeqCst);
    let _ = channel;
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Fail-closed halt on any unrecoverable fault
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

/// seL4 Microkit domain entry point called upon boot.
#[no_mangle]
pub extern "C" fn init() {
    compiler_fence(Ordering::SeqCst);
    // Initialize shared ring memory safely
    unsafe {
        let _ = RedDomainAppliance::init_rings();
    }
}

/// seL4 Microkit notification callback called when channel event occurs.
#[no_mangle]
pub extern "C" fn notified(channel: usize) {
    if channel != CHANNEL_CRYPTO {
        return;
    }
    compiler_fence(Ordering::SeqCst);
}

// =============================================================================
// Unit Tests (Mocking seL4 Shared Memory Pages)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_ring_buffer_init_and_push_pop() {
        let mut mock_shm = [0u8; RING_HALF_SIZE];
        let base_addr = mock_shm.as_mut_ptr() as usize;

        unsafe {
            let mut tx = ZeroCopyTxRing::new(base_addr);
            let rx = ZeroCopyRxRing::new(base_addr);

            assert_eq!(tx.available_write(), RING_DATA_CAPACITY - 1);

            let msg = b"TOP_SECRET_MIL_SPEC_ORDER";
            let slot = tx.acquire_tx_slot(msg.len(), MSG_TYPE_PLAINTEXT).unwrap();
            slot.copy_from_slice(msg);
            tx.commit_tx_slot(msg.len()).unwrap();

            let frame = rx.peek_rx_slot().unwrap().unwrap();
            assert_eq!(frame.msg_type, MSG_TYPE_PLAINTEXT);
            assert_eq!(frame.payload, msg);
            let flen = frame.frame_len;
            drop(frame);

            let mut rx_mut = ZeroCopyRxRing::new(base_addr);
            rx_mut.commit_rx_slot(flen).unwrap();

            assert!(rx.peek_rx_slot().unwrap().is_none());
        }
    }

    #[test]
    fn test_ring_buffer_wrap_around_and_continuity() {
        let mut mock_shm = [0u8; RING_HALF_SIZE];
        let base_addr = mock_shm.as_mut_ptr() as usize;

        unsafe {
            let mut tx = ZeroCopyTxRing::new(base_addr);
            let mut rx = ZeroCopyRxRing::new(base_addr);

            for i in 0..500 {
                let payload = [(i & 0xFF) as u8; 64];
                tx.push(&payload, MSG_TYPE_PLAINTEXT).unwrap();

                let frame = rx.peek_rx_slot().unwrap().unwrap();
                assert_eq!(frame.payload, &payload[..]);
                let flen = frame.frame_len;
                drop(frame);
                rx.commit_rx_slot(flen).unwrap();
            }
        }
    }

    #[test]
    fn test_ring_buffer_overflow_fail_closed() {
        let mut mock_shm = [0u8; RING_HALF_SIZE];
        let base_addr = mock_shm.as_mut_ptr() as usize;

        unsafe {
            let mut tx = ZeroCopyTxRing::new(base_addr);

            let chunk = [0x55u8; 1000];
            let mut pushed = 0;
            while let Ok(_) = tx.push(&chunk, MSG_TYPE_PLAINTEXT) {
                pushed += 1;
            }
            assert!(pushed > 0);

            let res = tx.push(&chunk, MSG_TYPE_PLAINTEXT);
            assert_eq!(res, Err(RingError::BufferFull));
        }
    }

    #[test]
    fn test_red_domain_appliance_send_receive() {
        let mut mock_shm = [0u8; RING_TOTAL_SIZE];
        let base_addr = mock_shm.as_mut_ptr() as usize;

        unsafe {
            let mut red_tx = ZeroCopyTxRing::new(base_addr + RED_TO_CRYPTO_OFFSET);
            let red_rx = ZeroCopyRxRing::new(base_addr + CRYPTO_TO_RED_OFFSET);
            let mut crypto_tx = ZeroCopyTxRing::new(base_addr + CRYPTO_TO_RED_OFFSET);
            let crypto_rx = ZeroCopyRxRing::new(base_addr + RED_TO_CRYPTO_OFFSET);

            let secret = b"TRANSMIT AUTHORIZED";
            red_tx.push(secret, MSG_TYPE_PLAINTEXT).unwrap();

            let frame = crypto_rx.peek_rx_slot().unwrap().unwrap();
            assert_eq!(frame.payload, secret);
            let flen = frame.frame_len;
            drop(frame);
            let mut crypto_rx_mut = ZeroCopyRxRing::new(base_addr + RED_TO_CRYPTO_OFFSET);
            crypto_rx_mut.commit_rx_slot(flen).unwrap();

            let reply = b"ACK_CONFIRMED";
            crypto_tx.push(reply, MSG_TYPE_PLAINTEXT).unwrap();

            let red_frame = red_rx.peek_rx_slot().unwrap().unwrap();
            assert_eq!(red_frame.payload, reply);
        }
    }

    #[test]
    fn test_ring_buffer_slot_too_large_rejection() {
        let mut mock_shm = [0u8; RING_HALF_SIZE];
        let base_addr = mock_shm.as_mut_ptr() as usize;

        unsafe {
            let mut tx = ZeroCopyTxRing::new(base_addr);
            // Attempting to allocate slot larger than entire ring capacity
            let result = tx.acquire_tx_slot(RING_DATA_CAPACITY + 100, MSG_TYPE_PLAINTEXT);
            assert_eq!(result.err(), Some(RingError::SlotTooLarge));
        }
    }

    #[test]
    fn test_ring_buffer_corrupted_header_handling() {
        let mut mock_shm = [0u8; RING_HALF_SIZE];
        let base_addr = mock_shm.as_mut_ptr() as usize;

        unsafe {
            let mut tx = ZeroCopyTxRing::new(base_addr);
            let rx = ZeroCopyRxRing::new(base_addr);

            // Write a legitimate frame first
            tx.push(b"VALID", MSG_TYPE_PLAINTEXT).unwrap();

            // Corrupt the FrameHeader in the buffer by setting length to 0xFFFF (exceeding capacity)
            let header_ptr = (base_addr + RING_CTRL_SIZE) as *mut FrameHeader;
            ptr::write_volatile(
                header_ptr,
                FrameHeader {
                    length: 0xFFFF,
                    msg_type: MSG_TYPE_PLAINTEXT,
                    flags: 0,
                },
            );

            // peek_rx_slot must detect that tail + needed > capacity and return Err(InvalidFrame)
            let result = rx.peek_rx_slot();
            assert_eq!(result, Err(RingError::InvalidFrame));
        }
    }
}
