# Module Documentation: Mesh and DDIL Networking Subsystem (`mesh_ddil_networking`)

## 1. Module Name & Purpose

- **Module Name:** `mesh_ddil_networking`
- **Subsystem Classification:** Mesh Routing, Disruption/Delay-Tolerant Networking (DDIL), Simplex Data Diodes, Byzantine Quorum Consensus, and Socket Transport
- **Files in Module (12 files, 9,204 verified lines):**
  - `byzantine_mesh_consensus.py` (972 lines)
  - `network/__init__.py` (11 lines)
  - `network/connection.py` (615 lines)
  - `network/handshake.py` (344 lines)
  - `network/io.py` (349 lines)
  - `network/manager.py` (54 lines)
  - `network/monitoring.py` (365 lines)
  - `network/session_manager.py` (1,435 lines)
  - `p2p_core.py` (2,664 lines)
  - `resilient_communication.py` (742 lines)
  - `tactical_data_diode.py` (674 lines)
  - `tactical_mesh_ddil.py` (979 lines)

- **Primary Technical Purpose:**
  The `mesh_ddil_networking` module implements decentralized peer transport across contested, degraded, intermittent, and low-bandwidth (DDIL) networks. It provides Cauchy Reed-Solomon forward error correction for unidirectional simplex UDP data diodes, Byzantine Fault Tolerant (BFT) threshold quorum consensus, store-and-forward reliable message delivery queues with exponential backoff, Delay-Tolerant Bundle Protocol (BPSec shape) routing with authority decay, framed TCP socket engines, and session security context management.

---

## 2. Public Interface

### 2.1. `tactical_data_diode.py`
- **Classes:**
  - `GF256` (`:48`): Finite field arithmetic over $\text{GF}(2^8)$ utilizing irreducible polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D`).
  - `CauchyErasureCoder` (`:110`): Generates Cauchy generator matrices and reconstructs payloads from $K$ valid shards.
    - `encode(data: bytes) -> List[bytes]` (`:160`): Splits data into $K$ data shards and generates $M$ parity shards.
    - `decode(shards: Dict[int, bytes], original_len: int) -> bytes` (`:210`): Reconstructs original data from any $K$ distinct shards.
  - `DiodePacket` (`:280`): Encapsulates shard index, total shards, transmission ID, payload shard, and HMAC authentication tag.
  - `CursorOnTargetEvent` (`:340`): Parses and serializes tactical Cursor-on-Target (CoT) XML event envelopes.
  - `DiodeTransmitter` (`:420`): Unidirectional transmitter socket bound exclusively with send permissions.
  - `DiodeReceiver` (`:520`): Unidirectional receiver socket bound exclusively with receive permissions.

### 2.2. `byzantine_mesh_consensus.py`
- **Classes:**
  - `CriticalCommandType(Enum)` (`:45`): Command classifications subject to Byzantine quorum.
  - `ByzantineQuorumEngine` (`:110`): Quorum state machine collecting peer ballots and enforcing threshold consensus:
    - `propose_command(command_id: str, command_type: CriticalCommandType, payload: bytes) -> Dict[str, Any]` (`:180`)
    - `cast_ballot(command_id: str, peer_id: str, vote: bool, signature: bytes) -> bool` (`:240`)
    - `finalize_consensus(command_id: str) -> Tuple[bool, Dict[str, Any]]` (`:320`)
    - `detect_equivocation(peer_id: str, ballot1: Dict[str, Any], ballot2: Dict[str, Any]) -> bool` (`:410`)

### 2.3. `tactical_mesh_ddil.py`
- **Classes:**
  - `BundlePriority(IntEnum)` (`:38`): Priority levels (`CRITICAL`, `OPERATIONAL`, `ROUTINE`, `BACKGROUND`).
  - `TacticalAuthorityLevel(IntEnum)` (`:55`): Hierarchical command authority tiers.
  - `AuthorityDecayEngine` (`:110`): Evaluates temporal decay of command authority across network partitions.
  - `DDILBundle` (`:210`): Bundle Protocol data unit encapsulating source, destination, priority, lifetime, and payload.
  - `DDILNodeMesh` (`:380`): Store-and-forward mesh routing engine maintaining bundle transit buffers.
- **Exported Functions:**
  - `create_bpsec_bundle(src: str, dst: str, payload: bytes, priority: BundlePriority) -> DDILBundle` (`:540`)
  - `decrypt_bpsec_bundle(bundle: DDILBundle, keyring: TacticalKeyring) -> bytes` (`:590`)

### 2.4. `p2p_core.py`
- **Classes:**
  - `FramedSocket` (`:380`): Length-prefixed socket wrapper handling fragmentation and framing errors:
    - `send_framed(payload: bytes) -> None` (`:410`)
    - `receive_framed() -> bytes` (`:440`)
  - `PreAuthRateLimiter` (`:520`): Enforces IP-based rate limiting on pre-authenticated connection attempts (`P2P_MAX_MSGS_PER_MIN`).
  - `StunClient` (`:620`): Performs RFC 5389 NAT discovery to determine external IPv4/IPv6 mapped endpoints.
  - `Message` (`:710`): Application-layer P2P message serializer and parser.
  - `SimpleP2PChat` (`:1200`): Socket event loop managing incoming/outgoing messages and peer handshakes.

### 2.5. `resilient_communication.py`
- **Classes:**
  - `MessageQueue` (`:90`): Priority-ordered disk-backed persistent queue for store-and-forward buffering.
  - `ExponentialBackoff` (`:180`): Calculates jittered backoff delays: $t = \min(t_{\max}, t_{\text{base}} \times 2^{\text{retries}}) \pm \text{jitter}$.
  - `MessageDeduplicator` (`:240`): FIFO sliding window cache rejecting duplicate message IDs.
  - `ResilientCommunicationManager` (`:320`): High-level transport orchestrator managing retry dispatching.

### 2.6. `network/` Package
- `network/connection.py`: `ConnectionManager` (`:45`) handles TCP socket life cycles, connect timeouts, and reconnect backoffs.
- `network/handshake.py`: `HandshakeManager` (`:35`) orchestrates key exchange negotiation.
- `network/io.py`: `NetworkIO` (`:40`) non-blocking read/write loops.
- `network/monitoring.py`: `ConnectionMonitoring` (`:35`) tracks latency, packet loss, and ping/pong keepalives.
- `network/session_manager.py`: `SessionManager` (`:60`) maintains active peer session contexts (`SessionContext`) and binds session authentication keys (`_derive_session_auth_key`).

---

## 3. Data Formats & Byte Layouts

### 3.1. `tactical_data_diode.py` Erasure Coding & Wire Envelopes
1. **Cauchy Reed-Solomon Parameters:**
   - Field: $\text{GF}(2^8)$ with irreducible polynomial $0x11D$ ($x^8 + x^4 + x^3 + x^2 + 1$).
   - Data Shards ($K$): 8
   - Parity Shards ($M$): 4
   - Total Shards ($N = K + M$): 12
   - Fault Tolerance: Any 8 out of 12 shards reconstruct original payload (tolerates up to 4 dropped shards).
   - Rate: $R = K / N = 8 / 12 = 2/3 \approx 66.7\%$ code rate.

2. **`DiodePacket` Header Layout (`:280-310`):**
   - Magic: 4 bytes (`b"DIOD"`)
   - Protocol Version: 1 byte uint8 (`0x01`)
   - Shard Index: 1 byte uint8 ($0 \le \text{idx} < 12$)
   - Total Shards: 1 byte uint8 (`12`)
   - Data Shards ($K$): 1 byte uint8 (`8`)
   - Transmission UUID: 16 bytes raw UUID
   - Shard Length: 2 bytes uint16 big-endian (`struct.pack(">H", len)`)
   - Payload Shard: $S$ bytes
   - Authentication HMAC-SHA256: 32 bytes
   - **Header Fixed Overhead:**
     $$\text{Overhead} = 4 + 1 + 1 + 1 + 1 + 16 + 2 + 32 = 58\text{ bytes}$$
   - **Total Packet Size:** $58 + S$ bytes.

### 3.2. `p2p_core.py` Framed Socket Layout
- Length Prefix: 4 bytes uint32 big-endian (`struct.pack(">I", length)` at `:415`).
- Maximum Frame Ceiling: Configured cap (default: $16\text{ MB} = 16777216$ bytes).
- Framing Overhead: 4 bytes per application message.

### 3.3. `byzantine_mesh_consensus.py` Quorum Receipt Format
- Consensus Round: 8 bytes uint64 big-endian.
- Command ID: 16 bytes UUID or string.
- Command Type: 2 bytes uint16.
- Payload Digest: 32 bytes SHA-256.
- Signatures: Map of `peer_id` to 4627-byte ML-DSA-87 signatures.
- For a 4-node network ($N=4, f=1$, Quorum $Q = 2f + 1 = 3$ nodes):
  $$\text{Signatures Size} = 3 \times 4627 = 13881\text{ bytes}$$

---

## 4. Algorithms & Pinned Libraries

1. **Cauchy Reed-Solomon Erasure Coding:**
   - Evaluated over Galois Field $\text{GF}(2^8)$ using Cauchy generator matrix $A_{i,j} = \frac{1}{x_i \oplus y_j}$.
2. **Byzantine Fault Tolerant Quorum Consensus:**
   - Super-majority quorum requirement: $N \ge 3f + 1$, where $f$ is maximum tolerated faulty or adversarial nodes. Quorum threshold $Q \ge 2f + 1$.
3. **ML-DSA-87 (NIST FIPS 204):**
   - Cryptographic signing of Byzantine ballots and consensus receipts via `liboqs_wrapper.py`.
4. **AES-256-GCM (NIST SP 800-38D):**
   - Payloads in `tactical_mesh_ddil.py` (`create_bpsec_bundle`) and `p2p_core.py` encrypted with 256-bit keys and 96-bit nonces.
5. **RFC 5389 Session Traversal Utilities for NAT (STUN):**
   - Implemented in `p2p_core.py:StunClient` using standard XOR-MAPPED-ADDRESS attributes (`0x0020`).

---

## 5. Dependencies

### 5.1. External Dependencies
- `cryptography` (hazmat primitives: `AESGCM`, `hashes`, `hmac`).
- `socket`, `struct`, `asyncio`, `math`, `secrets`: Standard library networking and math.

### 5.2. Internal Repository Dependencies
- `pqc_algorithms.py`: Provides algorithm constants and ML-DSA-87 instances.
- `platform_hsm_interface.py`: Provides secure random number generation.

---

## 6. Failure Behavior

1. **Simplex Diode Boundary Enforcement:**
   - In `tactical_data_diode.py`, `DiodeTransmitter` configures an outbound-only UDP socket; calling `recv()` or `recvfrom()` raises `RuntimeError("Transmitter socket cannot receive")` (`:470`). `DiodeReceiver` configures an inbound-only socket; calling `send()` or `sendto()` raises `RuntimeError("Receiver socket cannot send")` (`:570`).

2. **Byzantine Equivocation Detection:**
   - If a node broadcasts two conflicting ballots for the same command ID and consensus round, `ByzantineQuorumEngine.detect_equivocation()` flags the node, revokes its voting authority, and appends an equivocation proof to the audit log (`:415-435`).

3. **Pre-Authentication Rate Limiting:**
   - In `p2p_core.py`, if an unauthenticated IP address sends more than `P2P_MAX_MSGS_PER_MIN` (default: 60) messages in a 60-second window, `PreAuthRateLimiter` drops incoming packets without allocating session memory (`:545`).

4. **Corrupt Frame Prefix:**
   - In `p2p_core.py:FramedSocket`, if the length prefix exceeds the maximum allowed ceiling (16 MB) or fails to read 4 bytes, raises `SocketError("Frame size exceeds maximum allowable limit")` and severs connection.

---

## 7. Configuration / Environment Variables

| Variable Name | Defined In File | Default Value | Technical Purpose & Impact |
|:---|:---|:---|:---|
| `P2P_MAX_MSGS_PER_MIN` | `p2p_core.py:530` | `60` | Maximum messages per minute allowed from unauthenticated peer IP addresses. |
| `P2P_DISABLE_STUN` | `p2p_core.py:640` | `0` | If set to `1`, disables STUN NAT discovery queries. |
| `P2P_AUTO_SERVER_MODE` | `p2p_core.py:1220` | `0` | Automatically binds server listener if outbound connection fails. |
| `P2P_ALLOW_LEGACY_PLAINTEXT_SERVER` | `p2p_core.py:1235` | `0` | If set to `1`, permits unencrypted fallback listener (refused in strict mode). |
| `P2P_STRICT_SECURITY` | `p2p_core.py:1240` | `0` | If set to `1`, drops non-TLS and non-PQ handshakes fail-closed. |
| `P2P_TPM_QUOTE` | `network/session_manager.py:95` | `0` | If set to `1`, requires peer to supply a valid TPM attestation quote during session establishment. |
| `P2P_TPM_TRUSTED_AK_PUBS` | `network/session_manager.py:102` | None | Filepath to authorized Attestation Key public keys for quote validation. |

---

## 8. Tests Covered & Not Covered

### 8.1. Tests Covered (Directly Executed and Verified)
- `tests/test_diode_binding.py` (6 passed in 0.8s):
  - Validates simplex socket directionality, Cauchy erasure encoding/decoding, packet reconstruction under drop conditions, and HMAC verification.
- `tests/test_ddil_key_lifecycle.py` (8 passed in 1.1s):
  - Validates DDIL bundle generation, authority decay, BPSec encryption, and epoch advancement.
- `tests/test_resilient_ddil.py` (5 passed in 0.6s):
  - Validates priority queues, exponential backoff retries, and deduplication.
- `tests/test_production_tier4_cjadc2_and_consensus.py` (Byzantine consensus test cases passed in 10.2s):
  - Validates equivocation refusal with forensics, quorum bounds fail-fast, offline quorum certificate verification, ballot collection, and voter expiry.
- `tests/test_cli_key_fill_and_diode.py` (2 passed):
  - Validates CLI interaction with diode transmitters.
- `tests/test_connection_alias_cleanup.py`:
  - Validates connection lifecycle management in `network/connection.py`.

### 8.2. Not Covered / Zero Direct Tests
- `network/manager.py` (54 lines): 0 test files in `tests/` directly instantiate `NetworkManager` (facade coordinator).

---

## 9. Not Implemented / Stubs

1. **Hardware Optical Isolation:**
   - `tactical_data_diode.py` provides software socket directionality and forward error correction; it cannot replace physical fiber optic hardware diodes (e.g. transmit LED disconnected from receive photodiode) required for high-assurance cross-domain network boundary crossing.
2. **Bug in `cjadc2_allied_gateway.py:184` (Referenced during Byzantine Suite Execution):**
   - During execution of `tests/test_production_tier4_cjadc2_and_consensus.py`, 3 tests failed due to a missing definition: `NameError: name 'is_env_true' is not defined` inside `cjadc2_allied_gateway.py:184`. (This belongs to Module 12 and is cataloged in `docs/audit/discrepancies.md`).

---

## 10. Known Limitations

1. **Erasure Coding Packet Drop Bounds:**
   - Cauchy Reed-Solomon coding with $K=8, M=4$ tolerates a maximum of 4 lost packets per 12-packet block. If 5 or more shards are dropped on high-loss radio channels, the entire block is unrecoverable without retransmission.
2. **DDIL Disruption Storage Accumulation:**
   - In extended disconnection scenarios, store-and-forward bundles accumulate in local persistent queues. Persistent queues require disk quotas to prevent storage exhaustion on embedded appliances.

---

## 11. Discrepancies

1. **Promotional Headers and Non-Technical Phrasing:**
   - `tactical_data_diode.py:3` and `tactical_mesh_ddil.py:3` contain promotional banners and non-technical phrasing (cataloged in `docs/audit/discrepancies.md`).
2. **Gateway Quarantine NameError:**
   - `cjadc2_allied_gateway.py:184` invokes `is_env_true` without defining or importing it, causing test failures when gateway quarantine logic is triggered.

---

## 12. Open Questions

1. **Transport Layer Consolidation:**
   - The codebase contains both `p2p_core.py` (direct TCP) and `network/` (`connection.py`, `io.py`, `handshake.py`). Does `network/` represent an architectural migration away from `p2p_core.py`?
2. **Data Diode Dynamic MTU:**
   - Does `tactical_data_diode.py` adapt shard sizes dynamically when operating over link layers with smaller MTU constraints than standard Ethernet (e.g., VHF/UHF tactical radios)?