# Module Documentation: Transport Anonymity and Traffic Shaping Subsystem (`transport_anonymity`)

## 1. Module Name & Purpose

- **Module Name:** `transport_anonymity`
- **Subsystem Classification:** Traffic Analysis Countermeasures, Overlay Transport, Constant-Rate Cell Shaping, Wire Camouflage, and Dual-Person Authorization
- **Files in Module (11 files, 12,612 verified lines):**
  - `anonymous_identity_manager.py` (1,026 lines)
  - `covert_channel_defense.py` (1,385 lines)
  - `decentralized_architecture.py` (3,306 lines)
  - `metadata_resistance.py` (1,022 lines)
  - `network_adversary_resistance.py` (1,621 lines)
  - `network_endpoint_discovery.py` (540 lines)
  - `paced_socket_wrapper.py` (328 lines)
  - `spo_dpo.py` (738 lines)
  - `tactical_cloaking_router.py` (219 lines)
  - `transport_anonymity.py` (1,124 lines)
  - `zk_authenticator.py` (1,303 lines)

- **Primary Technical Purpose:**
  The `transport_anonymity` module provides network-layer obfuscation, metadata hiding, and pre-transmission authorization gates. It implements constant-rate cell shaping (50ms ticks, 1232-byte cells), Traffic Flow Confidentiality (TFC) bucket quantization, Poisson-distributed background chaff injection, SOCKS5 Tor v3 carriage with remote DNS resolution, Kademlia-based decentralized DHT routing with Proof-of-Work Sybil defense, hardware-paced socket camouflage, single-person and dual-person operation (SPO/DPO) authorization gates, and zero-knowledge identity authentication.

---

## 2. Public Interface

### 2.1. `transport_anonymity.py`
- **Classes:**
  - `OverlayError(Exception)` (`:73`): Base exception raised on overlay violations or proxy failures.
  - `ShaperTx` (`:180`): Outbound traffic shaper enqueuing application payloads, fragmenting data across fixed cells, and injecting cover frames on idle ticks.
  - `ShaperRx` (`:340`): Inbound traffic shaper reassembling data chunks and discarding cover frames.
  - `ConstantRateSession` (`:490`): Coordinates shaped communication channels over underlying network sockets.
- **Exported Functions:**
  - `is_onion(host: str) -> bool` (`:133`): Checks if an address targets a Tor `.onion` service.
  - `is_loopback_or_private(host: str) -> bool` (`:137`): Validates if a destination is a loopback, private, or overlay IP.
  - `transport_mode() -> str` (`:147`): Reads `P2P_TRANSPORT_MODE`.
  - `overlay_active_flag() -> bool` (`:151`): Reads `P2P_OVERLAY_ACTIVE`.
  - `tor_proxy_endpoint() -> Tuple[str, int]` (`:156`): Parses `P2P_TOR_PROXY` (default: `("127.0.0.1", 9050)`).

### 2.2. `tactical_cloaking_router.py`
- **Classes & Functions:**
  - `TacticalCloakViolation(SecurityError)` (`:18`): Raised when direct unencapsulated public connections are attempted.
  - `tactical_cloak_enabled() -> bool` (`:22`): Checks `P2P_TACTICAL_CLOAK` or `P2P_TS_MODE`.
  - `validate_outbound_destination(host: str, port: int) -> bool` (`:46`): Blocks outbound public destinations unless routed via overlay.
  - `validate_inbound_source(host: str) -> bool` (`:66`): Blocks inbound public connections unless arriving via overlay.
  - `get_chaff_jitter_interval(min_sec: float = 2.5, max_sec: float = 6.0) -> float` (`:86`): Calculates random jitter interval.
  - `get_poisson_interval(rate_lambda: float = 0.5) -> float` (`:99`): Generates exponential inter-arrival interval.
  - `pad_to_tfc_bucket(payload: bytes, target_bucket: Optional[int] = None) -> bytes` (`:111`): Quantizes payload into discrete TFC bucket sizes.
  - `unpad_tfc_bucket(padded_frame: bytes) -> bytes` (`:138`): Extracts raw payload from padded TFC frame.
  - `generate_chaff_frame(bucket_size: int = 512) -> bytes` (`:155`): Generates pseudorandom dummy packet marked with `CHAFF_MAGIC_TAG`.
  - `is_chaff_frame(data: bytes) -> bool` (`:169`): Identifies chaff frames.

### 2.3. `spo_dpo.py`
- **Classes:**
  - `AuthorizationError(Exception)` (`:65`): Base authorization rejection exception.
  - `OperationChallenge` (`:110`): Dataclass encapsulating `nonce` (32 bytes), `payload_digest`, `created_utc`, `expires_utc`.
  - `OperationApproval` (`:145`): Dataclass encapsulating `challenge_nonce`, `officer_id`, `token_ref`, `signature` (4627 bytes ML-DSA-87), `signed_utc`.
- **Key Functions:**
  - `issue_challenge(payload: bytes, lifetime_s: float = 30.0) -> OperationChallenge` (`:190`)
  - `verify_spo(challenge: OperationChallenge, approval: OperationApproval, authorized_officers: List[Any]) -> bool` (`:230`)
  - `verify_dpo(challenge: OperationChallenge, app1: OperationApproval, app2: OperationApproval, authorized_officers: List[Any], max_skew_s: float = 2.0) -> bool` (`:275`): Enforces dual independent officer signatures and 2.0s simultaneity window.

### 2.4. `paced_socket_wrapper.py`
- **Classes:**
  - `PacedChannel` (`:38`): Configuration container defining interval (15ms or 50ms) and MTU (1232 bytes).
  - `PacedSocketAdapter` (`:75`): Wraps underlying socket, queues outbound data, and emits fixed 1232-byte frames per tick.

### 2.5. `decentralized_architecture.py`
- **Classes:**
  - `DHTRoutingTable` (`:420`), `KBucket` (`:350`), `DHTStorage` (`:580`): Kademlia routing table implementation.
  - `DecentralizedPeerDiscovery` (`:820`): Broadcasts and listens for local mesh announcements.
  - `DeviceSyncManager` (`:1400`): Direct device-to-device transport synchronization.

### 2.6. `zk_authenticator.py`
- **Classes:**
  - `ZKProofError`, `ZKProofInvalid`, `ZKProofGenerationError` (`:53-70`)
  - `ZKAuthenticator` (`:253`): Schnorr-based zero-knowledge proof manager over $p = 2^{256} - 189$; requires experimental opt-in.
  - `MLDSAMultisigAuthenticator` (`:980`): Production-approved multi-signature authentication using NIST FIPS 204 ML-DSA-87.

### 2.7. Ancillary Files
- `anonymous_identity_manager.py`: `AnonymousIdentityManager` (`:90`) generates unlinkable identity keypairs without personal identifiers.
- `network_endpoint_discovery.py`: `NetworkEndpointDiscovery` (`:80`) parses and categorizes network adapters and public STUN candidates.
- `network_adversary_resistance.py`: `OnionEncryption` (`:110`) and `MultiHopRouter` (`:280`) provide layered packet wrapping.
- `covert_channel_defense.py`: `FixedRateTransmitter` (`:280`) and `PacketNormalizer` (`:120`) schedule constant-rate traffic.
- `metadata_resistance.py`: `MessagePaddingEngine` (`:60`) and `TorSOCKS5Proxy` (`:240`) provide transport masking.

---

## 3. Data Formats & Byte Layouts

### 3.1. `transport_anonymity.py` Wire Cell Layout
1. **Plain Cell Layout (`CELL_PLAIN = 1216` bytes at `:91`):**
   - Sequence Number (`seq`): 8 bytes uint64 big-endian (`>Q`, `SEQ_STRUCT`)
   - Cell Flags (`flags`): 1 byte uint8 (`0x01` = `FLAG_DATA`, `0xFF` = `FLAG_COVER`)
   - Chunk Length (`chunk_len`): 2 bytes uint16 big-endian (`>H`, `LEN_STRUCT`)
   - Cell Header Overhead:
     $$\text{Header Length} = 8 + 1 + 2 = 11\text{ bytes}$$
   - Maximum Payload Capacity:
     $$\text{CHUNK\_MAX} = 1216 - 11 = 1205\text{ bytes}$$
   - Padding: $1205 - \text{chunk\_len}$ bytes of random CSPRNG bytes.

2. **Authenticated Wire Cell (`CELL_SIZE = 1232` bytes at `:92`):**
   - Plain Cell: 1216 bytes
   - AES-256-GCM Tag: 16 bytes (`CELL_TAG`)
   - **Arithmetic Sum:**
     $$\text{Total Wire Cell Size} = 1216 + 16 = 1232\text{ bytes}$$

3. **Packet Encapsulation MTU Verification:**
   - Wire Cell: 1232 bytes
   - IPv6 Header: 40 bytes
   - UDP Header: 8 bytes
   - **Arithmetic Sum:**
     $$\text{Total Datagram Size} = 1232 + 40 + 8 = 1280\text{ bytes}$$
     This matches the IPv6 minimum MTU (RFC 8200 section 5), preventing packet fragmentation across network routers.

4. **Transmission Timing & Throughput:**
   - Interval (`TICK_S`): 0.05 seconds (50.0 ms = 20 cells per second).
   - Maximum Data Throughput:
     $$\text{Throughput} = 1205\text{ bytes/cell} \times 20\text{ cells/s} = 24100\text{ bytes/s} \approx 24.1\text{ KB/s}$$

### 3.2. `tactical_cloaking_router.py` TFC Quantum Framing
- **Bucket Sizes:** `(256, 512, 1024, 1400)` bytes.
- **Frame Layout:**
  - Length Field: 2 bytes uint16 big-endian (`p_len`).
  - Payload: $P$ bytes.
  - Zero Padding: Target Bucket Size $- (P + 2)$ bytes.
- **Chaff Tag:** `b"TACTICAL_CHAFF_V1::"` = 19 bytes.

### 3.3. `spo_dpo.py` Authorization Challenge & Receipt Layout
- **Challenge Nonce:** 32 bytes CSPRNG random bytes.
- **Payload Digest:** 32 bytes (SHA-256) or 48 bytes (SHA-384).
- **Officer Signature:** 4627 bytes (ML-DSA-87 signature per officer).
- **Dual-Person Receipt Sum:**
  $$\text{Signatures Payload Size} = 2 \times 4627 = 9254\text{ bytes}$$

---

## 4. Algorithms & Pinned Libraries

1. **AES-256-GCM (NIST SP 800-38D):**
   - Bulk wire cell encryption and authentication in `transport_anonymity.py`. Key: 32 bytes, Tag: 16 bytes.
2. **AES-256-CTR:**
   - Stream cipher whitening of cell bytes in `transport_anonymity.py:23`.
3. **ML-DSA-87 (NIST FIPS 204):**
   - Digital signatures for SPO/DPO authorization in `spo_dpo.py`.
4. **ChaCha20-Poly1305 (RFC 8439):**
   - Multi-hop onion layer encryption in `network_adversary_resistance.py`.
5. **Kademlia XOR Metric:**
   - Distance metric calculation $d(x, y) = x \oplus y$ over 160-bit or 256-bit node IDs in `decentralized_architecture.py`.
6. **SOCKS5 Protocol (RFC 1928):**
   - Tor transport carriage with remote DNS address type `0x03` (`transport_anonymity.py:TorTransport`).

---

## 5. Dependencies

### 5.1. External Dependencies
- `cryptography` (hazmat primitives: `AESGCM`, `ChaCha20Poly1305`, `hashes`, `HKDF`).
- `socket`, `struct`, `ipaddress`, `secrets`, `asyncio`: Standard library networking and serialization.

### 5.2. Internal Repository Dependencies
- `platform_hsm_interface`: Hardware RNG and key custody hooks.
- `pqc_algorithms`: Post-quantum signature wrappers.
- `production_gate`: Operational profile checks (`is_ts_mode`).

### 5.3. Unwired / Opt-In Modules
- `covert_channel_defense.py` and `metadata_resistance.py`: Fully functional standalone modules, but not wired into the default hot path (`p2p_core.py` / `secure_p2p.py`).

---

## 6. Failure Behavior

1. **`tactical_cloaking_router.py`:**
   - Under `P2P_TACTICAL_CLOAK=1` or `P2P_TS_MODE=1`, direct outbound or inbound public IP sockets raise `TacticalCloakViolation` (`:59, 79`) and refuse connection initialization.

2. **`transport_anonymity.py`:**
   - If `P2P_TRANSPORT_MODE=tor` is set but the local Tor SOCKS5 daemon at `127.0.0.1:9050` cannot be reached, raises `OverlayError` (`:520`) fail-closed.
   - Outbound queue backpressure: If `OUT_QUEUE_CAP` (1024 cells, ~1.2 MB) is exceeded, blocks enqueueing threads until shaper drains.

3. **`spo_dpo.py`:**
   - Simultaneity Violation: If difference between officer signing timestamps exceeds 2.0 seconds, raises `AuthorizationError("DPO simultaneity window exceeded")` (`:295`).
   - Replay Rejection: Challenge nonces are stored in an 8192-entry FIFO; replaying an existing nonce raises `AuthorizationError`.
   - Identity Collision: If both approvals contain identical officer IDs or token references, raises `AuthorizationError`.

4. **`zk_authenticator.py`:**
   - Default Production Gate: Raises `PermissionError("Custom ZK arithmetic (PRIME=2**256-189) is unaudited and disabled in production...")` (`:303`).

---

## 7. Configuration / Environment Variables

| Variable Name | Defined In File | Default Value | Technical Purpose & Impact |
|:---|:---|:---|:---|
| `P2P_TRANSPORT_MODE` | `transport_anonymity.py:148` | `""` | Selects transport mode: `"tor"`, `"overlay"`, or `"direct"`. |
| `P2P_OVERLAY_ACTIVE` | `transport_anonymity.py:151`, `tactical_cloaking_router.py:55` | `0` | If set to `1`, confirms presence of an active VPN/APN/WireGuard overlay. |
| `P2P_TOR_PROXY` | `transport_anonymity.py:157` | `127.0.0.1:9050` | Host and port for local Tor SOCKS5 proxy daemon. |
| `P2P_TOR_PT` | `transport_anonymity.py:165` | None | Pluggable transport configuration string (e.g., obfs4, webtunnel). |
| `P2P_TORRC` | `transport_anonymity.py:170` | None | Filepath to operator torrc configuration file. |
| `P2P_TACTICAL_CLOAK` | `tactical_cloaking_router.py:24`, `network_endpoint_discovery.py:35` | `0` | If set to `1`, forbids unencapsulated public socket exposure. |
| `P2P_AIR_GAPPED` | `network_endpoint_discovery.py:30` | `0` | If set to `1`, suppresses STUN resolution and external internet probes. |
| `P2P_ENFORCE_DHT_POW` | `decentralized_architecture.py:65` | `0` | If set to `1`, requires Proof-of-Work computation for DHT node admission. |
| `P2P_DHT_POW_DIFFICULTY_BYTES` | `decentralized_architecture.py:72` | `2` | Number of leading zero bytes required for DHT Proof-of-Work solution. |
| `P2P_DHT_MAX_PACKETS_PER_MIN` | `decentralized_architecture.py:80` | `60` | Inbound rate limit for DHT query messages per remote IP. |
| `P2P_REQUIRE_SIGNED_DHT` | `decentralized_architecture.py:88` | `0` | If set to `1`, requires ML-DSA-87 / Ed25519 signatures on DHT peer records. |
| `P2P_LAB_ALLOW_UNSIGNED_SPO` | `spo_dpo.py:85` | `0` | If set to `1`, permits unsigned SPO challenges for laboratory testing only. |
| `P2P_ENABLE_CUSTOM_ZK` / `P2P_ENABLE_EXPERIMENTAL` | `zk_authenticator.py:248-249` | `0` | If set to `1`, enables unaudited custom ZK arithmetic over $p = 2^{256} - 189$. |

---

## 8. Tests Covered & Not Covered

### 8.1. Tests Covered (Directly Executed and Verified)
- `tests/test_spo_dpo.py` (8 passed in 0.8s):
  - Validates SPO and DPO verification, simultaneity window enforcement ($\le 2.0\text{ s}$), sync breach rejection, hardware key requirements, tampered receipt refusal, and unsigned receipt refusal.
- `tests/test_network_endpoint_discovery.py` (18 passed in 0.4s):
  - Validates air-gap STUN suppression, IPv4/IPv6 endpoint formatting, JSON serialization, local interface categorization, and malformed packet rejection.
- `tests/test_paced_socket_wrapper.py` (5 passed in 0.5s):
  - Validates native binary checks, channel config, send/receive interface, live loopback paced exchange, and stream buffering.
- `tests/test_anonymous_loopback.py` (1 passed in 2.1s):
  - Validates end-to-end anonymous loopback transmission with constant-rate shaping.
- `tests/test_tier4_pq_treekem_and_tfc.py` (10 passed, 1 skipped in 2.2s):
  - Validates TFC discrete bucket padding, chaff identification, and Poisson timing distribution.
- `tests/test_decentralized_architecture` (in `tests/test_critical_audit_remediations.py`):
  - Validates DHT Proof-of-Work and signed peer record parsing.

### 8.2. Not Covered / Zero Direct Tests
- `covert_channel_defense.py`: 0 dedicated test files in `tests/`.
- `metadata_resistance.py`: 0 dedicated test files in `tests/`.

---

## 9. Not Implemented / Stubs

1. **Physical Two-Person Presence in `spo_dpo.py:22-25`:**
   - Software cannot prove two distinct human beings are physically present in the room; `spo_dpo.py` enforces a dual-signature cryptographic protocol between two hardware tokens, noting that true physical presence requires external administrative controls.
2. **Pluggable Transport Automation:**
   - `transport_anonymity.py:30-38` notes that pluggable transports (e.g. obfs4, WebTunnel) require external binaries and active Tor bridges; software does not bundle or automatically spawn PT helper daemons.

---

## 10. Known Limitations

1. **Shaped Channel Bandwidth Cap:**
   - At a 50 ms tick rate and 1205 bytes of payload per cell, maximum throughput is strictly capped at $\approx 24.1$ KB/s. This makes the shaped transport unsuitable for large bulk file transfers.
2. **Tor Network Latency:**
   - Routing packets through 3-hop Tor onion circuits introduces substantial latency (500ms to 2500ms round-trip time), degrading interactive chat responsiveness.
3. **Proof-of-Work Calibration on Diverse Devices:**
   - In `decentralized_architecture.py`, fixed Proof-of-Work difficulty targets may cause battery drain or excessive latency on low-power mobile hardware while providing limited Sybil protection against high-powered desktop adversaries.

---

## 11. Discrepancies

1. **Promotional Banners and Non-Technical Terms:**
   - `spo_dpo.py:6` references specific operational directives and non-technical phrasing.
   - `zk_authenticator.py:3, 55` contains non-technical error messages with promotional uppercase fatal error strings (cataloged in `docs/audit/discrepancies.md`).
   - `network_adversary_resistance.py:3-4` contains uppercase promotional header blocks.
   - All occurrences are cataloged in `docs/audit/discrepancies.md`.
2. **Untested Subsystems:**
   - `covert_channel_defense.py` and `metadata_resistance.py` are present in product code but have zero automated test suites in `tests/`.
3. **Hot Path Disconnection:**
   - Existing documentation (`docs/modules/anonymity_decentral.md`) notes that several decentralization and anonymity components are opt-in and disconnected from the default hot path (`p2p_core.py` TCP).

---

## 12. Open Questions

1. **Subsystem Redundancy:**
   - Are `covert_channel_defense.py` and `metadata_resistance.py` deprecated prototypes that were superseded by `transport_anonymity.py` and `tactical_cloaking_router.py`, or are they slated for future integration?
2. **Dynamic Pacing Configuration:**
   - Is there a planned adaptive pacing mode to dynamically adjust cell sizes and intervals based on link capacity and operational threat postures?