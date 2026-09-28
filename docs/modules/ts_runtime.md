# Module: `ts_runtime.py`, `ts_rt`, & `ts_attest.py` — OS & Execution Runtime

[Back to Documentation Index](../README.md) | [System Architecture](../ARCHITECTURE.md)

This module implements **Pillar 2: OS & Execution Runtime** for the 2027 Top-Secret transmission pipeline. It enforces kernel-level security guarantees, anti-DMA bus protection, native memory locking, compiler-fence zeroization, branchless anti-replay tracking, and IETF RATS TPM attestation.

---

## 1. Core Source Files & Responsibilities

| Source File | Lines | Primary Security Responsibilities |
|---|---|---|
| [`ts_runtime.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_runtime.py) | ~650 | Operating system platform gate (seL4 vs AO test waiver + VBS/HVCI), anti-DMA bus scan, native library binding. |
| [`ts_rt/src/lib.rs`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_rt/src/lib.rs) | ~400 | Native zero-dependency Rust crate (`ts_rt.dll`) providing OS page locking (`VirtualLock`), volatile memory wiping, and branchless anti-replay sliding window. |
| [`ts_attest.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_attest.py) | ~180 | IETF RATS (RFC 9334) platform evidence packaging and TPM quote attestation. |

---

## 2. Key Subsystems & Implementations

### 2.1. Kernel Platform Gate (`assert_execution_environment`)
- **seL4 Target Environment:** In high-assurance operational theaters, the runtime requires an AArch64 or RISC-V platform running a formally verified seL4 microkernel.
- **Windows / Linux Enterprise Gate:** When running on non-seL4 commodity architectures, the runtime strictly requires:
  1. A cryptographically signed Authorizing Official (AO) test waiver (`P2P_AO_TEST_WAIVER`).
  2. Active UEFI Secure Boot with valid platform keys (`PK`, `KEK`, `DB`).
  3. Hypervisor-Protected Code Integrity (HVCI) and Virtualization-Based Security (VBS) verified via Windows registry and WMI queries.
- **Fail-Closed Behavior:** Any host failing both criteria raises `TSRequiredError: unqualified platform` and halts.

### 2.2. Anti-DMA Hardware Bus Interposition Scan (`scan_dma_controllers`)
- **Threat Vector:** Physical memory dumping via direct memory access (DMA) peripherals (Thunderbolt 3/4, IEEE 1394 FireWire, PCMCIA, un-IOMMU-isolated ExpressCard slots).
- **Mechanism:** Inspects PCI device trees and hardware controller descriptors via OS APIs.
- **Enforcement:** Flags active, unprotected external DMA controllers and aborts data plane startup until either Kernel DMA Protection is active or the ports are physically disabled in firmware.

### 2.3. Native Rust Runtime Engine (`ts_rt.dll`)
To eliminate garbage collector memory retention in Python, performance-critical security primitives execute inside a native, `#![no_std]` compatible Rust DLL:

1. **OS Page Locking (`VirtualLock` / `mlock`):**
   - Locks allocated cryptographic secret buffers into physical RAM.
   - Prevents the OS kernel from paging cryptographic keys to unencrypted pagefiles or swap partitions on disk.
2. **Volatile Scrubbing with Compiler Fences (`secure_wipe`):**
   - Uses `core::ptr::write_volatile` followed by `core::sync::atomic::compiler_fence(Ordering::SeqCst)`.
   - Guarantees that dead-store elimination (DSE) optimizations in LLVM or GCC cannot remove memory overwriting routines.
3. **Branchless 64-Bit Anti-Replay Sliding Window (`replay_window_check_and_update`):**
   - Implements a constant-time 64-frame sliding bitmap.
   - Protects against duplicate datagram injection, frame reordering, and delayed packet playback without conditional branching timing leaks.

### 2.4. IETF RATS Attestation Packaging (`ts_attest.py`)
- **Standard:** IETF Remote Attestation Procedures Architecture (RFC 9334).
- **Mechanism:** Packages TPM 2.0 quote evidence, PCR composites (PCRs 0, 1, 2, 7), and firmware boot logs into a verifiable attestation evidence envelope.
- **Verification:** Peer nodes verify the attestation envelope against signed reference integrity measurements (RIM) before accepting encrypted session handshakes.

---

## 3. Test Coverage

- **Suites:** [`test_ts_runtime.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/test_ts_runtime.py) (14 tests), [`test_ts_attest.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/test_ts_attest.py) (5 tests).
- **Pass Rate:** **19 of 19 tests passing (100%)**
- **Tested Behaviors:** Platform qualification logic, AO waiver parsing, anti-DMA controller discovery, native DLL buffer locking and wiping, branchless replay window verification under duplicate/out-of-order traffic, and IETF RATS evidence serialization.
