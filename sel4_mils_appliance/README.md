# Formal seL4 Microkit MILS Domain Separation Architecture

**Target Security Standard:** Common Criteria EAL6+ / EAL7 Equivalent (Formal Binary Verification), NSA CNSA Suite 2.0, FIPS 140-3 Level 4  
**Component Execution Framework:** seL4 Microkit with `no_std` Ferrocene-Qualified Rust Protection Domains  
**Security Invariant:** Mathematical guarantee of zero direct communication between RED (plaintext) and BLACK (network) domains. Complete immunity to monolithic OS kernel vulnerabilities.

---

## 1. Architectural Overview & Security Invariant

The **seL4 MILS Appliance** enforces physical and mathematical isolation across three distinct protection domains using the formally verified **seL4 microkernel** and the **seL4 Microkit** execution environment.

```
+========================================================================================================+
|                              seL4 MICROKIT HARDWARE APPLIANCE LAYOUT                                   |
+========================================================================================================+
|                                                                                                        |
|   +-----------------------+                    +-----------------------+                               |
|   |      RED DOMAIN       |                    |     BLACK DOMAIN      |                               |
|   |  (Plaintext / User)   |                    |  (Network / Cipher)   |                               |
|   |                       |                    |                       |                               |
|   | - Plaintext Display   |                    | - Ethernet / UDP PHY  |                               |
|   | - Operator Console    |                    | - DDIL Mesh Routing   |                               |
|   | - NO Network Hardware |                    | - 20 Hz Wire Pacing   |                               |
|   | - NO Key Access       |                    | - NO Plaintext Access |                               |
|   +-----------▲-----------+                    +-----------▲-----------+                               |
|               │                                            │                                           |
|       Shared Memory Ring                           Shared Memory Ring                                  |
|       Buffer (RED <-> CRYPTO)                      Buffer (CRYPTO <-> BLACK)                           |
|       `red_crypto_ring`                            `crypto_black_ring`                                 |
|       (vaddr: 0x10000000)                          (vaddr: 0x20000000)                                 |
|       + Notification Ch 1                          + Notification Ch 2                                 |
|               │                                            │                                           |
|               ▼                                            ▼                                           |
|   +--------------------------------------------------------------------+                               |
|   |                           CRYPTO DOMAIN                            |                               |
|   |                     (Sovereign Core Mediator)                      |                               |
|   |                                                                    |                               |
|   | - Post-Quantum Triple-Hybrid Engine (ML-KEM-1024, ML-DSA-87)       |                               |
|   | - Quarantined Key Storage (`crypto_locked_keys`, vaddr: 0x30000000)|                               |
|   | - Dual-Rail Fault-Injection Verification Guards                    |                               |
|   | - Active Scorched-Earth Memory Zeroization Engine                  |                               |
|   | - ZERO Direct User I/O & ZERO Direct Network Hardware Access       |                               |
|   +--------------------------------------------------------------------+                               |
|                                      ▲                                                                 |
|                                      │ seL4 Capability-Based Kernel IPC                                |
|   +--------------------------------------------------------------------+                               |
|   |                    seL4 VERIFIED MICROKERNEL                       |                               |
|   |          (Formally Proven Isolation, Integrity & Non-Bypass)       |                               |
|   +--------------------------------------------------------------------+                               |
|                                                                                                        |
+========================================================================================================+
```

### 1.1 Strict Mathematical Isolation Invariants

1. **Zero RED-to-BLACK Channel (Non-Bypassability)**:
   $$\text{Endpoints}(\text{RED}) \cap \text{Endpoints}(\text{BLACK}) = \emptyset$$
   The seL4 capability system assigns zero shared memory and zero IPC notification endpoints between the RED domain and the BLACK domain. Direct data transmission between RED and BLACK is mathematically impossible under the seL4 formal proof.
2. **Shared Memory Partitioning**:
   $$\text{Map}(\text{RED}) \cap \text{Map}(\text{BLACK}) = \emptyset$$
   RED maps only `red_crypto_ring`. BLACK maps only `crypto_black_ring`. No physical memory frame is simultaneously mapped into both domains.
3. **Key Material Quarantine**:
   $$\text{Map}(\text{crypto\_locked\_keys}) = \{\text{CRYPTO}\}$$
   Secret cryptographic keys exist solely within the locked memory region (`0x30000000`) of the CRYPTO domain with `cached="false"`. Neither RED nor BLACK possesses read or write capabilities to this memory.
4. **Complete Mediation**:
   Every packet traversing from user to network (or network to user) is forced through the CRYPTO domain's cryptographic transformation pipeline.

---

## 2. Microkit System Description (`system.xml`)

The appliance topology is defined statically in `sel4_mils_appliance/system.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<system>
    <!-- Physical Shared Memory Regions -->
    <memory_region name="red_crypto_ring" size="0x10000" page_size="0x1000" />
    <memory_region name="crypto_black_ring" size="0x10000" page_size="0x1000" />
    <memory_region name="crypto_locked_keys" size="0x4000" page_size="0x1000" />

    <!-- 1. RED Protection Domain: Plaintext User Space -->
    <protection_domain name="red" priority="100">
        <program_image path="red_domain.elf" />
        <map mr="red_crypto_ring" vaddr="0x10000000" perms="rw" cached="true" />
    </protection_domain>

    <!-- 2. CRYPTO Protection Domain: Sovereign Cryptographic Engine & Key Quarantine -->
    <protection_domain name="crypto" priority="120">
        <program_image path="crypto_domain.elf" />
        <map mr="red_crypto_ring" vaddr="0x10000000" perms="rw" cached="true" />
        <map mr="crypto_black_ring" vaddr="0x20000000" perms="rw" cached="true" />
        <map mr="crypto_locked_keys" vaddr="0x30000000" perms="rw" cached="false" />
    </protection_domain>

    <!-- 3. BLACK Protection Domain: Untrusted Ciphertext Network Transport -->
    <protection_domain name="black" priority="90">
        <program_image path="black_domain.elf" />
        <map mr="crypto_black_ring" vaddr="0x20000000" perms="rw" cached="true" />
    </protection_domain>

    <!-- Notification Channels (seL4 Endpoints) -->
    <channel>
        <end pd="red" id="1" />
        <end pd="crypto" id="1" />
    </channel>
    <channel>
        <end pd="crypto" id="2" />
        <end pd="black" id="2" />
    </channel>
</system>
```

### Domain Priorities
- **CRYPTO (Priority 120)**: Highest priority. Ensures cryptographic transformations and emergency zeroization execute deterministically without thread starvation.
- **RED (Priority 100)**: Medium priority. Manages plaintext operator console and local user I/O.
- **BLACK (Priority 90)**: Lowest priority. Untrusted transport worker handling network frame serialization and constant-rate wire pacing.

---

## 3. Zero-Copy Ring Buffer IPC (`no_std` Rust)

Each domain implements lockless, wait-free Single-Producer Single-Consumer (SPSC) zero-copy ring buffers in bare-metal Rust (`#![no_std]`, `#![no_main]`).

### 3.1 Memory Layout & Alignment

Each 64 KiB (`0x10000`) shared memory region is bisected into two 32 KiB (`0x8000`) unidirectional channels:
- **TX Sub-Buffer (`0x0000` - `0x7FFF`)**: Channel Producer $\rightarrow$ Consumer
- **RX Sub-Buffer (`0x8000` - `0xFFFF`)**: Channel Consumer $\rightarrow$ Producer

#### Control Header (`RingControl`, 64 bytes)
Aligned to 64 bytes (the hardware cache line size on AArch64, RISC-V, and x86_64) to prevent false sharing:
```rust
#[repr(C, align(64))]
pub struct RingControl {
    pub magic: u32,             // 0x53454C34 ("sEL4")
    pub version: u32,           // 1
    pub capacity: u32,          // Usable payload capacity (32704 bytes)
    pub head: AtomicU32,        // Write index (Producer updates, Consumer reads)
    pub tail: AtomicU32,        // Read index (Consumer updates, Producer reads)
    pub dropped_count: AtomicU32,// Dropped frames on overflow
    pub flags: AtomicU32,       // Operational flags
    _reserved: [u32; 9],        // Padding to 64 bytes
}
```

#### Frame Header (`FrameHeader`, 4 bytes)
```rust
#[repr(C, packed)]
pub struct FrameHeader {
    pub length: u16,    // Payload length in bytes
    pub msg_type: u8,   // 0x01: Plaintext, 0x02: Ciphertext, 0xFF: Chaff
    pub flags: u8,      // Status/control flags
}
```

### 3.2 Zero-Copy Mechanics
- **Producer (`acquire_tx_slot`)**: Bounds checks contiguous memory between `head` and `tail`, writes `FrameHeader` in-place, and returns a mutable slice `&mut [u8]` directly referencing the shared memory frame. The caller writes data without intermediate heap or stack copying.
- **Producer (`commit_tx_slot`)**: Executes `fence(Ordering::Release)` and advances `head` atomically.
- **Consumer (`peek_rx_slot`)**: Executes `fence(Ordering::Acquire)`, validates frame bounds, and returns `RxFrame` referencing the shared memory slice directly (zero-copy inspection).
- **Consumer (`commit_rx_slot`)**: Advances `tail` atomically past the frame, releasing the buffer space.

### 3.3 Continuous Stream Wrap-Around Sentinel Protocol (`MSG_TYPE_WRAP`)
When a frame exceeds the remaining space at the end of the circular buffer (`head + needed > capacity`):
1. The producer checks if space exists at the start of the buffer (`tail > needed`).
2. If space permits, the producer writes an in-band wrap sentinel frame (`MSG_TYPE_WRAP = 0xFE`) at `head`, resets `head = 0`, and writes the payload at index 0.
3. The consumer automatically detects `MSG_TYPE_WRAP` during `peek_rx_slot`, advances `tail = 0`, and immediately yields the frame at index 0 without dropping packets or stalling the communication pipeline.

---

## 4. Anti-Tamper & Traffic Invariance

### 4.1 Scorched-Earth Emergency Zeroization
On unmapped page fault, laser fault-injection detection, or tamper alert, the CRYPTO domain executes multi-pass volatile overwrites:
1. Pass 1: Write `0xAA` pattern across `crypto_locked_keys` (16 KiB) with `fence(Ordering::SeqCst)`.
2. Pass 2: Write `0x55` pattern with memory barrier.
3. Pass 3: Write `0x00` pattern with memory barrier.
4. Comprehensive wipe of shared rings (`red_crypto_ring` and `crypto_black_ring`) before CPU halt.

### 4.2 Constant-Rate 20 Hz Traffic Pacing
The BLACK domain emits uniform 1232-byte wire frames at 20 Hz:
- When legitimate ciphertext is queued from CRYPTO, it is framed and padded to 1232 bytes.
- When the queue is empty, the BLACK domain emits synthetic `0xFF` chaff cells filled with high-entropy bytes.
- Signals intelligence (SIGINT) interceptors observe constant-entropy, constant-rate bitstreams, preventing packet size or timing correlation.

---

## 5. Common Criteria EAL6+ / EAL7 Security Functional Requirements (SFR)

| SFR Identifier | Common Criteria Title | Architectural Implementation in seL4 Appliance |
|:---|:---|:---|
| **FDP_ACC.2** | Complete Access Control | Zero direct shared memory or IPC endpoints between RED and BLACK. |
| **FDP_ACF.1** | Security Attribute-Based Access Control | seL4 capability-based access control enforces static domain rights in hardware page tables. |
| **FDP_IFC.2** | Complete Information Flow Control | Pure lattice policy: RED $\leftrightarrow$ CRYPTO $\leftrightarrow$ BLACK. No bypass path exists. |
| **FDP_IFF.1** | Simple Security Attributes | Information cannot transition across domains without CRYPTO mediation. |
| **FPT_FLS.1** | Fail-Secure State | Any panic, fault-injection divergence, or tamper event triggers immediate multi-pass volatile memory zeroization and CPU halt. |
| **FPT_SEP.3** | Complete TSF Domain Separation | Bare-metal `#![no_std]` and `#![no_main]` binaries isolate user, crypto, and transport spaces. |

---

## 6. Automated Verification Tooling

### 6.1 Formal Static Verification Suite (`tests/test_sel4_mils_spec.py`)
Executes 25 comprehensive static assertions, property-based tests, and fault-injection simulations:
```bash
pytest tests/test_sel4_mils_spec.py -v
```
Verified invariants:
1. `test_system_xml_exists_and_is_valid`: Validates well-formed Microkit XML.
2. `test_protection_domains_and_priorities`: Confirms priority lattice (CRYPTO 120 > RED 100 > BLACK 90).
3. `test_shared_memory_regions_page_alignment`: 4 KiB hardware page alignment and sizing floor.
4. `test_static_assertion_zero_red_black_shared_memory`: $\text{Map}(\text{RED}) \cap \text{Map}(\text{BLACK}) = \emptyset$.
5. `test_static_assertion_zero_red_black_direct_channel`: Zero direct notification endpoints.
6. `test_formal_topology_cut_vertex_invariance`: Graph cut-vertex reachability test.
7. `test_key_quarantine_invariance`: `crypto_locked_keys` mapped exclusively to CRYPTO with `cached="false"`.
8. `test_memory_virtual_address_layout`: Collision-free virtual address layout.
9. `test_fail_closed_negative_mutations`: Negative tests with mutated invalid topologies.
10. `test_rust_no_std_static_invariants`: Bare-metal `#![no_std]` and `#![no_main]` verification.
11. `test_rust_crates_compile_cleanly`: Clean compilation across all domains.
12. `test_rust_unit_tests_pass`: Subprocess execution of 18 bare-metal unit tests.
13. `test_bell_lapadula_information_flow_lattice`: Multilevel security label validation.
14. `test_channel_id_integrity_and_bounds`: Microkit channel IDs strictly bounded in [1, 63].
15. `test_sovereign_appliance_node_integration`: End-to-end integration with SovereignApplianceNode.
16. `test_board_json_specification_alignment`: Hardware layout alignment with AArch64 Cortex-A72.
17. `test_linker_script_wx_policy`: Linker script enforces $W \oplus X$ policy and non-executable stack.
18. `test_traffic_chaff_shannon_entropy`: Shannon entropy > 7.8 bits/byte in wire chaff cells.
19. `test_hypothesis_chaff_entropy_high_across_seeds`: Property-based entropy validation across seeds.
20. `test_mils_compliance_report_generation`: Automated JSON compliance audit receipt generator.
21. `test_aarch64_baremetal_compilation_and_elf_verification`: Verification of 64-bit Little-Endian AArch64 static ELF binaries.
22. `test_system_xml_malformed_rejection_negative_matrix`: Fail-closed rejection of unaligned sizes and invalid IDs.
23. `test_anti_replay_window_comprehensive_matrix`: RFC 6479 decoupled 128-packet sliding window boundary tests.
24. `test_multi_round_ring_buffer_torture_and_continuity`: 10,000-round wrap-around continuous stream simulation.
25. `test_validate_mils_cli_strict`: CLI invariant verification with strict non-zero exit code.

### 6.2 Standalone MILS CLI Verifier (`validate_mils.py`)
Run automated compliance checks for CI/CD pipelines:
```bash
python sel4_mils_appliance/validate_mils.py --xml sel4_mils_appliance/system.xml --strict
```

### 6.3 Bare-Metal Rust Test Suite (`cargo test`)
Executes 18 SPSC zero-copy ring buffer unit tests, wrap-around stress tests, MAC verification, and crypto mediation in Rust:
```bash
cargo test --manifest-path sel4_mils_appliance/Cargo.toml
```

### 6.4 Bare-Metal Cross-Compilation (AArch64 Cortex-A72 Target)
Builds native ELF binaries for deployment on the seL4 Microkit target:
```bash
cargo build --target aarch64-unknown-none --release --manifest-path sel4_mils_appliance/Cargo.toml
```

### 6.5 Unified Makefile
```bash
make -C sel4_mils_appliance all
```
