# Module: `transport_anonymity.py` & `spo_dpo.py` — Network Anonymity & Shaping

[Back to Documentation Index](../README.md) | [System Architecture](../ARCHITECTURE.md)

This module implements **Pillar 4: Network Anonymity & Traffic Shaping** for the 2027 Top-Secret transmission pipeline. It provides metadata resistance, backbone traffic analysis mitigation, SOCKS5 Tor v3 carriage, interface-pinned sovereign routing, constant-rate cell shaping, AES-256-CTR stream whitening, and DoD Directive S-5210.41M Two-Person Integrity.

---

## 1. Core Source Files & Responsibilities

| Source File | Lines | Primary Security Responsibilities |
|---|---|---|
| [`transport_anonymity.py`](transport_anonymity.py) | ~800 | SOCKS5 Tor client with remote DNS, sovereign APN pinning, 50ms constant-rate cell scheduler, 1232B cell framing, AES-256-CTR whitening. |
| [`spo_dpo.py`](spo_dpo.py) | ~350 | DoD Directive S-5210.41M Single Persona / Dual Persona Operator (DPO) two-person integrity enforcement with a 2.0s hardware window. |

---

## 2. Key Subsystems & Implementations

### 2.1. SOCKS5 Tor v3 Transport Carriage (`TorTransport`)
- **Standard:** RFC 1928 SOCKS5 Protocol.
- **DNS Leak Mitigation:** Enforces remote hostname resolution (`ATYP = 0x03`). The host operating system never issues local DNS queries for `.onion` or destination endpoints, eliminating ISP DNS snooping.
- **Circuit Isolation:** Authenticates to local Tor daemon via SOCKS5 authentication credentials to isolate circuits per session.

### 2.2. Sovereign Private APN Pinning (`InterfacePinnedTransport`)
- **Use Case:** Tactical tactical cellular, SATCOM, or direct point-to-point links where Tor is prohibited or unavailable.
- **Mechanism:** Binds sockets directly to a specified physical interface via `SO_BINDTODEVICE` (Linux) or interface-specific IP binding (Windows).
- **Enforcement:** Disallows traffic traversal over default unencrypted gateways; packets are dropped if the pinned interface goes down.

### 2.3. Constant-Rate 50ms Tick Shaping (`ConstantRateScheduler`)
- **Threat Vector:** Side-channel traffic analysis (packet timing, message volume spikes, burst-rate correlation).
- **Scheduler Rate:** Fixed 20 cells per second (1 cell every 50.0 milliseconds ± random micro-jitter).
- **Cell Disciplines:**
  - When real data is queued: Encapsulates payload into 1232-byte cells (`CellType.DATA = 0x01`).
  - When queue is empty: Generates cryptographically indistinguishable dummy cells (`CellType.CHAFF = 0x02`).
  - To an external eavesdropper, link activity is identical whether the operators are idle or transmitting Top-Secret war orders.

### 2.4. 1232-Byte Uniform Cell Framing & AES-256-CTR Whitening
- **Frame Layout:**
  ```
  [0..3]   Magic Header ('\x53\x54\x32\x37' -> 'ST27')
  [4..11]  Monotonic Sequence Number (uint64 big-endian)
  [12..13] Payload Length (uint16 big-endian, max 1205 bytes)
  [14]     Cell Type (0x01 Data, 0x02 Chaff, 0x03 Heartbeat, 0x04 Rekey)
  [15..N]  Payload Data (variable, 0 to 1205 bytes)
  [N..1215] Cryptographic Padding (random or zero fill to 1216 bytes)
  [1216..1231] AES-256-GCM Authentication Tag (16 bytes)
  ```
- **Stream Whitening:**
  - After cell assembly, the entire 1232-byte block is XOR-masked with a deterministic AES-256-CTR pseudorandom keystream derived from the session context.
  - Removes structural byte headers, making the packet appear as pure uniform entropy across the wire and defeating Deep Packet Inspection (DPI) signatures.

### 2.5. DoD Directive S-5210.41M Two-Person Integrity (`spo_dpo.py`)
- **Operational Rule:** Sensitive command execution and Top-Secret message release require Dual Persona Operation (DPO).
- **Enforcement Rules:**
  1. **Two Distinct Authenticated Personas:** Primary Officer (`Officer_Alpha`) and Verifying Officer (`Officer_Bravo`) must authorize using distinct hardware tokens (`token_1 != token_2`).
  2. **2.0-Second Synchronization Window:** Replicating physical dual-key launch switches, both authorizations must be registered within $\Delta t \le 2.000\text{ seconds}$.
  3. **Zeroization on Failure:** Window timeouts or authorization mismatches trigger automatic clearance of staged payloads and zeroization of temporary credential caches.

---

## 3. Test Coverage

- **Suites:**
  - `test_transport_anonymity.py`] (11 tests)
  - `test_spo_dpo.py`] (8 tests)
- **Pass Rate:** **19 of 19 tests passing (100%)**
- **Tested Behaviors:** SOCKS5 handshake framing, remote DNS formatting, 50ms scheduler tick compliance, 1232B cell serialization/deserialization, AES-256-CTR whitening/unwhitening, DPO dual-token approval, and 2.0s window timeout rejection.
