# Module Documentation: Transport Anonymity and Traffic Shaping Subsystem (`transport_anonymity`)

## 1. Purpose

- **Module Name:** `transport_anonymity`
- **Subsystem Classification:** Network Transport Obfuscation, Constant-Rate Cell Shaping, Overlay Carriage, Post-Quantum Anonymous Identity Management, and Timing Analysis Countermeasures.
- **Assigned Scope in Audit Register (`docs/audit/PROGRESS.md:31`):**
  - [`anonymous_identity_manager.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py) (Present: 1,027 verified lines)
  - [`transport_anonymity.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py) (Present: 1,127 verified lines)
  - `onion_routing.py` (**NON-EXISTENT** as a standalone file in the repository; functionality is distributed across [`transport_anonymity.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L288-L370), [`anonymous_identity_manager.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L451-L501), and [`network_adversary_resistance.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/network_adversary_resistance.py#L110-L280))
  - `traffic_padding.py` (**NON-EXISTENT** as a standalone file in the repository; functionality is implemented in [`transport_anonymity.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L439-L471), [`tactical_cloaking_router.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/tactical_cloaking_router.py#L111-L150), and [`crypto/padding.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/crypto/padding.py#L81-L105))
  - `chaff_stream.py` (**NON-EXISTENT** as a standalone file in the repository; functionality is implemented in [`transport_anonymity.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L442-L529), [`tactical_cloaking_router.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/tactical_cloaking_router.py#L86-L108), [`paced_socket_wrapper.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/paced_socket_wrapper.py#L75-L120), and [`rust_data_plane/src/chaff.rs`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/src/chaff.rs))
- **Verified Code Volume (In-Scope Present Code):** 2 files, 2,154 verified lines (`transport_anonymity.py`: 1,127 lines; `anonymous_identity_manager.py`: 1,027 lines).
- **Primary Technical Purpose:**
  The subsystem provides metadata-hiding network transport, constant-rate traffic shaping, and anonymous cryptographic identity management. It enforces fixed-interval cell transmission (50 ms ticks, 1232-byte authenticated cells) with cover traffic on idle ticks, SOCKS5 carriage over local Tor v3 daemons with remote hostname resolution (`ATYP = 0x03`) to eliminate local DNS leakage, hybrid post-compromise session rekeying (ML-KEM-1024 + X25519), and post-quantum cryptographic identity generation (ML-KEM-1024 + ML-DSA-87) with Tor v3 onion address derivation.

---

## 2. Public Interface

### 2.1. `transport_anonymity.py`

#### Classes and Key Methods

##### `OverlayError(Exception)` ([transport_anonymity.py:73-74](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L73-L74))
Raised upon overlay connection rejection, proxy handshake failure, or cell authentication/sequencing violations.

##### `ShaperTx` ([transport_anonymity.py:473-530](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L473-L530))
Outbound constant-rate cell transmitter.
- `__init__(obfs_key: bytes, direction: int = 0xA5, start_seq: Optional[int] = None)` ([transport_anonymity.py:476-491](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L476-L491)): Validates 32-byte key and direction flag (`0xA5` or `0x5A`).
- `enqueue_frame(frame: bytes) -> None` ([transport_anonymity.py:492-504](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L492-L504)): Enqueues length-prefixed frame. Blocks or raises `OverlayError` when `_queued_frames >= OUT_QUEUE_CAP` (1024 frames).
- `next_cell() -> bytes` ([transport_anonymity.py:505-530](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L505-L530)): Generates next 1232-byte authenticated wire cell. If pending buffer is empty, generates a cover cell (`FLAG_COVER = 0xFF`). Increments 64-bit sequence counter.

##### `ShaperRx` ([transport_anonymity.py:532-584](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L532-L584))
Inbound cell stream reassembler.
- `__init__(obfs_key: bytes, direction: int = 0xA5, peer_start_seq: int = 0)` ([transport_anonymity.py:543-556](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L543-L556)): Initializes expected 64-bit sequence counter.
- `feed_wire(wire_cell: bytes) -> List[bytes]` ([transport_anonymity.py:561-584](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L561-L584)): Decrypts cell via AES-256-GCM, validates sequence counter, parses chunk, discards cover cells, and reassembles length-prefixed application frames.

##### `ConstantRateSession` ([transport_anonymity.py:586-665](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L586-L665))
Manages continuous background pump thread driving socket I/O at 50 ms ticks.
- `start() -> None` ([transport_anonymity.py:610-616](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L610-L616)): Starts daemon background thread `_pump`.
- `stop() -> None` ([transport_anonymity.py:618-622](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L618-L622)): Signals stop event and joins background thread with 2.0 s timeout.
- `_pump() -> None` ([transport_anonymity.py:624-639](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L624-L639)): Monotonic time-driven loop transmitting `tx.next_cell()` every `TICK_S = 0.05` s.
- `pump_once_for_test() -> bytes` ([transport_anonymity.py:640-645](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L640-L645)): Emits exactly one cell synchronously for deterministic testing.
- `recv_available(timeout: float = 0.5) -> List[bytes]` ([transport_anonymity.py:646-665](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L646-L665)): Reads raw bytes, slices into 1232-byte cells, feeds into `rx`, and returns reassembled application frames.

#### Exported Module Functions
- `is_onion(host: str) -> bool` ([transport_anonymity.py:133-134](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L133-L134)): Identifies `.onion` hostnames.
- `is_loopback_or_private(host: str) -> bool` ([transport_anonymity.py:137-145](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L137-L145)): Checks for loopback, private RFC 1918, link-local, or localhost targets.
- `transport_mode() -> str` ([transport_anonymity.py:147-148](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L147-L148)): Returns normalized `P2P_TRANSPORT_MODE`.
- `overlay_active_flag() -> bool` ([transport_anonymity.py:151-153](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L151-L153)): Evaluates boolean `P2P_OVERLAY_ACTIVE`.
- `tor_proxy_endpoint() -> Tuple[str, int]` ([transport_anonymity.py:156-170](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L156-L170)): Parses host and port from `P2P_TOR_PROXY` (default: `127.0.0.1:9050`).
- `torrc_path() -> str` ([transport_anonymity.py:172-175](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L172-L175)): Resolves path from `P2P_TORRC` or returns `/etc/tor/torrc`.
- `torrc_enforces_pt() -> bool` ([transport_anonymity.py:177-203](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L177-L203)): Verifies `UseBridges 1` and `ClientTransportPlugin` in torrc when `P2P_TOR_PT=required`.
- `check_tor_proxy_live(timeout: float = 3.0) -> bool` ([transport_anonymity.py:205-216](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L205-L216)): Probes local SOCKS5 proxy via raw socket greeting (`\x05\x01\x00`).
- `require_overlay(host: str, port: int) -> Dict[str, Any]` ([transport_anonymity.py:219-285](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L219-L285)): Policy gate enforcing valid overlay path (`tor-onion`, `tor`, `private_apn`, `wireguard`, `air_gapped`, or lab direct).
- `socks5_connect(proxy_host: str, proxy_port: int, dest_host: str, dest_port: int, timeout: float = 10.0) -> socket.socket` ([transport_anonymity.py:288-356](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L288-L356)): Connects via RFC 1928 SOCKS5, passing destination hostname via `ATYP = 0x03` to prevent local DNS queries.
- `open_overlay_socket(host: str, port: int, timeout: float = 10.0) -> socket.socket` ([transport_anonymity.py:373-389](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L373-L389)): Establishes overlay transport connection.
- `derive_obfs_key(session_key: bytes, transcript: bytes) -> bytes` ([transport_anonymity.py:392-403](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L392-L403)): Derives 32-byte obfuscation key using HKDF-SHA384 with salt `sha384(transcript)[:32]` and info `b"obfs-v1"`.
- `seal_cell(plain_cell: bytes, obfs_key: bytes, seq: int, direction: int) -> bytes` ([transport_anonymity.py:409-420](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L409-L420)): Encrypts 1216-byte plain cell with AES-256-GCM into 1232-byte wire cell.
- `open_cell(wire_cell: bytes, obfs_key: bytes, seq: int, direction: int) -> bytes` ([transport_anonymity.py:422-436](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L422-L436)): Decrypts and authenticates 1232-byte wire cell with AES-256-GCM.
- `build_plain_cell(seq: int, is_cover: bool, chunk: bytes) -> bytes` ([transport_anonymity.py:439-450](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L439-L450)): Serializes sequence, flag, chunk length, payload, and zero-padding up to 1216 bytes.
- `parse_plain_cell(plain_cell: bytes) -> Tuple[int, bool, bytes]` ([transport_anonymity.py:452-471](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L452-L471)): Deserializes cell header, verifies trailing zero-padding in constant time via `hmac.compare_digest`.
- `anonymous_send(...) -> Dict[str, Any]` ([transport_anonymity.py:790-939](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L790-L939)): End-to-end sender driving TLS 1.3 handshake, Noise/PQ authentication, obfuscation key negotiation, and constant-rate cell shaping.
- `anonymous_recv(...) -> Any` ([transport_anonymity.py:968-1126](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L968-L1126)): End-to-end receiver operating bidirectional constant-rate shaped session.

---

### 2.2. `anonymous_identity_manager.py`

#### Classes and Key Methods

##### `IdentityDisposalError(Exception)` & `IdentityGenerationError(Exception)` ([anonymous_identity_manager.py:78-84](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L78-L84))
Exceptions for failed memory wipe verification or key generation.

##### `AnonymousIdentity` ([anonymous_identity_manager.py:86-223](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L86-L223))
Dataclass holding post-quantum and Tor keys for an identity.
- Attributes: `identity_id` (str), `display_name` (str), `created_at` (datetime), `kem_public_key` (bytes), `kem_private_key` (bytes), `sig_public_key` (bytes), `sig_private_key` (bytes), `onion_address` (Optional[str]), `onion_private_key` (Optional[bytes]), `is_active` (bool), `rotation_count` (int), `last_used` (Optional[datetime]), `key_hierarchy_root` (Optional[bytes]).
- `get_public_bundle() -> Dict[str, Any]` ([anonymous_identity_manager.py:124-150](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L124-L150)): Returns dictionary containing public keys and metadata, signed with ML-DSA-87.
- `verify_public_bundle(bundle: Dict[str, Any]) -> bool` ([anonymous_identity_manager.py:151-171](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L151-L171)): Static method verifying ML-DSA-87 signature over bundle fields.
- `get_all_key_material() -> List[bytes]` ([anonymous_identity_manager.py:210-223](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L210-L223)): Collects private and public keys for secure wiping.

##### `AnonymousIdentityManager` ([anonymous_identity_manager.py:225-1013](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L225-L1013))
Manages generation, storage, rotation, and cryptographic unlinkability checks.
- `generate_identity(display_name=None, generate_onion=True, key_hierarchy_root=None) -> AnonymousIdentity` ([anonymous_identity_manager.py:339-408](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L339-L408)): Generates ML-KEM-1024, ML-DSA-87, and Tor v3 onion address.
- `create_unlinkable_identity(display_name=None) -> AnonymousIdentity` ([anonymous_identity_manager.py:503-564](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L503-L564)): Derives identity from fresh CSPRNG entropy mixed with timestamp entropy via SHA3-512, wipes intermediate entropy, and verifies pairwise unlinkability against all existing identities.
- `rotate_identity(identity_id: str, secure_dispose: bool = True, verify_disposal: bool = True) -> AnonymousIdentity` ([anonymous_identity_manager.py:565-615](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L565-L615)): Generates new replacement identity, increments rotation count, wipes old key material using DoD 5220.22-M 3-pass pattern, and invokes memory scan verification.
- `verify_unlinkability(id1: str, id2: str) -> bool` ([anonymous_identity_manager.py:839-947](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L839-L947)): Tests two identities for key independence, prefix divergence ($\le 8$ bytes common prefix), distinct onion addresses, and statistical XOR byte balance ($\le 25\%$ zero bytes in first 32 bytes of XOR).
- `dispose_all(verify_disposal: bool = True) -> int` ([anonymous_identity_manager.py:955-979](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L955-L979)): Wipes and unloads all managed identities.

---

## 3. Data Formats and Byte Layouts

### 3.1. Constant-Rate Cell Framing (`transport_anonymity.py`)

#### 1. Plain Cell Layout (`CELL_PLAIN = 1216` bytes, [transport_anonymity.py:91](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L91))

| Offset (bytes) | Field Name | Type | Encoding | Purpose / Content |
|---|---|---|---|---|
| `0..7` | Sequence Number (`seq`) | uint64 | Big-endian (`>Q`) | Monotonically increasing cell sequence counter ([transport_anonymity.py:100](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L100)). |
| `8` | Cell Flags (`flags`) | uint8 | Raw byte | `0x01` (`FLAG_DATA`) or `0xFF` (`FLAG_COVER`) ([transport_anonymity.py:97-98](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L97-L98)). |
| `9..10` | Chunk Length (`chunk_len`) | uint16 | Big-endian (`>H`) | Length of application payload fragment ($0 \le \mathrm{chunk\_len} \le 1205$) ([transport_anonymity.py:101](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L101)). |
| `11..11+chunk_len` | Payload Chunk | bytes | Binary | Application frame slice (empty in cover cells) ([transport_anonymity.py:445-446](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L445-L446)). |
| `11+chunk_len..1215` | Tail Padding | bytes | `0x00` fill | Zero-padding filling plain cell to exactly 1216 bytes ([transport_anonymity.py:449](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L449)). |

**Header Overhead and Capacity:**
- Header Length: $8 + 1 + 2 = 11$ bytes (`CELL_HEADER_LEN = 11`, [transport_anonymity.py:95](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L95)).
- Maximum Payload Capacity: $\mathrm{CHUNK\_MAX} = 1216 - 11 = 1205$ bytes ([transport_anonymity.py:96](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L96)).

#### 2. Authenticated Wire Cell Layout (`CELL_SIZE = 1232` bytes, [transport_anonymity.py:92](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L92))

| Offset (bytes) | Field Name | Size (bytes) | Mechanism |
|---|---|---|---|
| `0..1215` | Encrypted Plain Cell | 1216 | AES-256-GCM ciphertext ([transport_anonymity.py:415-416](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L415-L416)). |
| `1216..1231` | Authentication Tag (`CELL_TAG`) | 16 | AES-256-GCM authentication tag ([transport_anonymity.py:93, 417](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L93)). |

**Arithmetic Verification:**
$$\text{Total Wire Cell Size} = 1216 + 16 = 1232\text{ bytes}$$

**AEAD Nonce Construction (`_cell_nonce` at [transport_anonymity.py:405-406](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L405-L406)):**
- 12 bytes total: $\text{seq (8 bytes, }>Q\text{)} \parallel \text{direction (1 byte, }0\text{xA5 or }0\text{x5A)} \parallel 0\text{x}000000\ (3\text{ zero bytes})$.

#### 3. Datagram MTU Fit Verification ([transport_anonymity.py:20-21, 89-90](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L20-L21))
- Wire Cell: 1232 bytes
- IPv6 Fixed Header: 40 bytes
- UDP Header Reserve: 8 bytes
- **Arithmetic Sum:**
  $$\text{Total Encapsulated Datagram} = 1232 + 40 + 8 = 1280\text{ bytes}$$
  This matches the IPv6 minimum MTU (RFC 8200 Section 5), ensuring datagrams never fragment across IPv6 network paths.

#### 4. Timing, Rate, and Throughput Calculations
- Tick Interval: `TICK_S = 0.05` s (50.0 ms = 20 cells/s) ([transport_anonymity.py:94](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L94)).
- Gross Wire Bitrate:
  $$\text{Wire Bitrate} = 1232\text{ bytes/cell} \times 20\text{ cells/s} \times 8\text{ bits/byte} = 197,120\text{ bps} \approx 197.1\text{ kbps}$$
- Maximum Net Payload Throughput:
  $$\text{Max Throughput} = 1205\text{ bytes/cell} \times 20\text{ cells/s} = 24,100\text{ bytes/s} \approx 24.1\text{ KB/s}$$
- Maximum Supported Message Size: 52,428,800 bytes (50 MB) ([transport_anonymity.py:822, 1071](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L822)).
  - Transmission duration for 50 MB at shaper rate:
    $$\frac{52,428,800\text{ bytes}}{24,100\text{ bytes/s}} \approx 2,175.5\text{ seconds} \approx 36.25\text{ minutes}$$

---

### 3.2. Tor v3 Onion Address Derivation Layout (`anonymous_identity_manager.py:451-501`)

Derived from a randomly generated Ed25519 public key per Tor Rendezvous Specification v3:
1. Public Key: 32 bytes raw Ed25519 public key bytes (`public_key_ed`).
2. Checksum: First 2 bytes of $\text{SHA3-256}(b\text{".onion checksum"} \parallel \mathrm{public\_key\_ed} \parallel b\text{"\x03"})$ ([anonymous_identity_manager.py:490-491](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L490-L491)).
3. Version: Single byte `b"\x03"` ([anonymous_identity_manager.py:494](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L494)).
4. Binary Sum: $32 + 2 + 1 = 35$ bytes.
5. Base32 String: $\text{Base32}(\mathrm{onion\_bytes})$ produces 56 lowercase characters, appended with `".onion"` ([anonymous_identity_manager.py:498-500](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L498-L500)).

---

### 3.3. Key Pair and Cryptographic Material Dimensions

| Structure | Algorithm / Mechanism | Public / Wire Size | Secret Key Size | Source Citation |
|---|---|---|---|---|
| KEM Identity Key | ML-KEM-1024 | 1,568 bytes | 3,168 bytes | [`liboqs_wrapper.py:365-366`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/liboqs_wrapper.py#L365-L366), [`anonymous_identity_manager.py:366`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L366) |
| Signature Identity Key | ML-DSA-87 | 2,592 bytes | 4,896 bytes (Sig: 4,627 bytes) | [`liboqs_wrapper.py:549-551`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/liboqs_wrapper.py#L549-L551), [`anonymous_identity_manager.py:369`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L369) |
| Tor v3 Transport Key | Ed25519 | 32 bytes | 32 bytes | [`anonymous_identity_manager.py:477-485`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L477-L485) |
| Session Obfuscation Key | HKDF-SHA384 | 32 bytes | 32 bytes | [`transport_anonymity.py:392-403`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L392-L403) |
| Epoch Rekey Exchange 1 | ML-KEM-1024 + X25519 | $9 + 1568 + 32 + 32 = 1641$ B | 3,168 B (KEM) + 32 B (X25519) | [`transport_anonymity.py:705-711`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L705-L711) |
| Epoch Rekey Exchange 2 | ML-KEM-1024 + X25519 | $9 + 32 + 1568 = 1609$ B | 32 B (X25519) | [`transport_anonymity.py:724, 760-763`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L724) |

---

## 4. Algorithms and Pinned Libraries

1. **AES-256-GCM (NIST SP 800-38D):**
   - Bulk cell encryption and message authentication. Implemented via `cryptography.hazmat.primitives.ciphers.aead.AESGCM` ([transport_anonymity.py:411, 424](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L411)).
   - *Audit Finding:* Module docstring at line 23 refers to "AES-256-CTR whitening", but implementation executes AES-256-GCM AEAD.
2. **HKDF-SHA384 (RFC 5869):**
   - Obfuscation key derivation from session key and nonces (`transport_anonymity.py:394-402`) and epoch ratchet key derivation (`transport_anonymity.py:681-687`).
3. **ML-KEM-1024 (NIST FIPS 203):**
   - Post-quantum key encapsulation for anonymous identity management (`anonymous_identity_manager.py:57, 320`) and session epoch rotation (`transport_anonymity.py:703, 751`). Native C wrapper via `oqs.dll` version 0.16.0.
4. **ML-DSA-87 (NIST FIPS 204):**
   - Post-quantum digital signatures for identity bundle authentication (`anonymous_identity_manager.py:58, 140, 167, 321`). Native C wrapper via `oqs.dll` version 0.16.0.
5. **Ed25519 (RFC 8032):**
   - Key derivation for Tor v3 `.onion` addresses (`anonymous_identity_manager.py:472-485`) via `cryptography.hazmat.primitives.asymmetric.ed25519`.
6. **X25519 (RFC 7748):**
   - Ephemeral Diffie-Hellman in hybrid epoch ratchet (`transport_anonymity.py:700, 744, 760`).
7. **SOCKS5 (RFC 1928):**
   - Tor SOCKS5 carriage with remote domain resolution (`ATYP = 0x03`) (`transport_anonymity.py:288-356`).
8. **SHA3-256 / SHA3-512 (NIST FIPS 202):**
   - Identity ID derivation (`anonymous_identity_manager.py:436`), Tor v3 checksum (`:491`), and entropy mixing (`:536`).

---

## 5. Dependencies and Hardware Requirements

### 5.1. Runtime Dependencies
- `cryptography>=42.0.0` (hazmat primitives: `AESGCM`, `x25519`, `ed25519`, `hashes`, `HKDF`).
- `oqs.dll` (pinned native dynamic library v0.16.0, SHA-384 verified in `dependency_security_verifier.py:240-245`).
- Python standard library: `socket`, `struct`, `ipaddress`, `secrets`, `threading`, `time`, `hashlib`, `hmac`.

### 5.2. Internal Repository Dependencies
- [`production_gate.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/production_gate.py#L82): Mode checks (`is_ts_mode()`, `is_production()`).
- [`cnsa2_policy_engine.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cnsa2_policy_engine.py#L42): Transport validation hook `validate_network_transport`.
- [`tactical_cloaking_router.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/tactical_cloaking_router.py#L46): Destination filter `validate_outbound_destination`.
- [`secure_transmit_2027.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/secure_transmit_2027.py#L270): Subsystem transport framing, peer prefix enforcement, TLS pinning.
- [`spo_dpo.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/spo_dpo.py#L825): Dual-person authorization gate `require_spo_dpo_for_send`.

### 5.3. External Infrastructure Requirements
- Local Tor daemon running SOCKS5 proxy at `127.0.0.1:9050` (or `P2P_TOR_PROXY`). Direct public internet connections are blocked in production mode.
- Tor Pluggable Transports: When `P2P_TOR_PT=required`, requires an operator-supplied `torrc` configuring `ClientTransportPlugin` and bridges; the application code does not bundle or spawn PT binaries.

---

## 6. Failure Behavior

1. **Overlay Gate Rejection:**
   - Under strict mode (`_strict_mode() == True`), public IPv4 or IPv6 socket connections without Tor or an attested overlay raise `OverlayError("overlay rejected")` ([transport_anonymity.py:241, 250, 257, 285](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L241)).
2. **Tor Proxy Unreachable:**
   - If `check_tor_proxy_live()` fails to negotiate a greeting (`\x05\x00`) with `P2P_TOR_PROXY` within 3.0 s, raises `OverlayError("overlay rejected")` ([transport_anonymity.py:260-261](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L260-L261)).
3. **Wire Cell Authentication and Sequencing Violations:**
   - If an incoming cell fails AES-256-GCM authentication, `open_cell` raises `OverlayError("overlay rejected")` ([transport_anonymity.py:433](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L433)).
   - If `cell_seq != self._expected`, `ShaperRx.feed_wire` raises `OverlayError("overlay rejected")` ([transport_anonymity.py:565-566](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L565-L566)).
   - If trailing padding contains non-zero bytes, `parse_plain_cell` raises `OverlayError("overlay rejected")` ([transport_anonymity.py:462-463](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L462-L463)).
4. **Dead Transfer Timeout (Finding F-06):**
   - In `anonymous_recv`, an idle deadline of `IDLE_REFRESH_S = 120.0` s is maintained. This deadline is refreshed exclusively by `FLAG_DATA` payload cells ([transport_anonymity.py:1060](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L1060)). Continuous cover cells do *not* refresh the window, causing stalled transfers to abort with `OverlayError` after 120 s ([transport_anonymity.py:1043-1044](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L1043-L1044)).
5. **Memory Disposal Verification Fail-Closed:**
   - In `AnonymousIdentityManager._verify_memory_scan()`, if `_memory_manager` does not provide `verify_wipe`, the function logs an error and returns `False` ([anonymous_identity_manager.py:721-732](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L721-L732)). This causes `rotate_identity(verify_disposal=True)` to raise `IdentityDisposalError` fail-closed ([anonymous_identity_manager.py:671-673](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L671-L673)).

---

## 7. Configuration and Environment Variables

| Variable Name | Defined At | Default Value | Operational Impact |
|---|---|---|---|
| `P2P_TRANSPORT_MODE` | [`transport_anonymity.py:148`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L148) | `""` | Transport carriage selector: `"tor"`, `"private_apn"`, `"wireguard"`, `"air_gapped"`. |
| `P2P_OVERLAY_ACTIVE` | [`transport_anonymity.py:151`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L151) | `"0"` | Boolean flag (`"1"`, `"true"`, `"yes"`) asserting active overlay tunnel interface. |
| `P2P_TOR_PROXY` | [`transport_anonymity.py:157`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L157) | `"127.0.0.1:9050"` | Local SOCKS5 proxy endpoint for Tor carriage. |
| `P2P_TOR_PT` | [`transport_anonymity.py:185`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L185) | `""` | When set to `"required"`, checks torrc for bridges and `ClientTransportPlugin`. |
| `P2P_TORRC` | [`transport_anonymity.py:173`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py#L173) | `"/etc/tor/torrc"` | Path to operator Tor configuration file. |
| `P2P_TS_MODE` / `SECURE_P2P_PRODUCTION` | [`production_gate.py:82`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/production_gate.py#L82) | `"0"` | Activates strict production mode; blocks unencapsulated public socket connections. |

---

## 8. Tests Covered and Not Covered

### 8.1. Tests Directly Executed and Verified

The following test suites were executed directly during this audit:

1. **`tests/test_transport_anonymity.py`:**
   - **Command:** `python -m pytest tests/test_transport_anonymity.py`
   - **Result:** 17 passed in 5.93s.
   - **Test Inventory:**
     - `test_overlay_lab_loopback_allowed`: Verifies lab loopback socket approval.
     - `test_overlay_strict_refuses_direct_public`: Verifies strict rejection of direct public IPs.
     - `test_overlay_strict_onion_accepted`: Verifies approval of `.onion` destinations.
     - `test_cells_fixed_size_and_uniform`: Verifies cell sizing (1232B wire, 1216B plain).
     - `test_fragment_reassemble_roundtrip`: Verifies chunking, framing, and cover frame discard.
     - `test_constant_rate_intervals`: Verifies cell timing loop.
     - `test_socks5_handshake_against_stub`: Verifies RFC 1928 greeting and remote domain resolution.
     - `test_wire_cells_are_uniform_noise`: Verifies entropy of sealed wire cells.
     - `test_cell_tamper_and_replay_rejected`: Verifies AEAD decryption failure and sequence checking.
     - `test_overlay_bypass_matrix`: Verifies matrix of destination/mode bypass attempts.
     - `test_obfs_key_derivation_is_deterministic`: Verifies HKDF-SHA384 output reproducibility.
     - `test_f06_ack_deadline_scales_with_payload`: Verifies payload-dependent timeout computation.
     - `test_f06_recv_absolute_cap_covers_50mb`: Verifies 50 MB absolute receive cap sizing.
     - `test_obfs_derivation_is_symmetric_for_both_ends`: Verifies client and server derive identical keys.
     - `test_receiver_ack_is_data_not_cover`: Verifies delivery acknowledgment is flagged `FLAG_DATA`.
     - `test_anonymous_data_phase_carries_channel_frames`: Verifies shaped channel data delivery.
     - `test_shaper_tx_queue_accounting_releases_capacity`: Verifies queue budget release upon cell consumption.

2. **`tests/test_anonymous_loopback.py`:**
   - **Command:** `python -m pytest tests/test_anonymous_loopback.py -s`
   - **Result:** 1 passed in 1.58s.
   - **Verification:** End-to-end loopback execution combining TLS 1.3 outer carriage, Noise PQ handshake, dual-person authorization, and constant-rate shaped transmission.

3. **Remediation and Regression Tests for `anonymous_identity_manager.py`:**
   - **Command:** `python -m pytest tests/test_fullreview_critical_remediations.py -k "TestOnionKeyRandomness or TestDisposalVerificationRefusedWithoutBackend"`
   - **Result:** 2 passed in 1.04s.
     - `TestOnionKeyRandomness::test_onion_key_not_derivable_from_public_key`: Verifies Tor v3 private key is a fresh CSPRNG Ed25519 keypair, not derived from public keys.
     - `TestDisposalVerificationRefusedWithoutBackend::test_scan_refuses_without_backend`: Verifies `_verify_memory_scan` returns `False` when no memory-scan backend exists.
   - **Command:** `python -m pytest tests/test_audit_confirmed_regressions.py -k "finding_11"`
   - **Result:** 1 passed in 0.65s.
     - `TestAuditConfirmedRegressions::test_finding_11_discovery_bundle_verification_fails_closed`: Verifies that forged or untrusted identity bundles fail verification.

### 8.2. Tests Not Covered / Zero Test Suites

1. `anonymous_identity_manager.py` has no dedicated test file `tests/test_anonymous_identity_manager.py`; tests are scattered across general regression suites (`test_audit_confirmed_regressions.py`, `test_defensive_audit_targets.py`, `test_fullreview_critical_remediations.py`).
2. The non-existent scope files `onion_routing.py`, `traffic_padding.py`, and `chaff_stream.py` have zero dedicated test suites.
3. Unwired modules `covert_channel_defense.py` and `metadata_resistance.py` have zero test files in `tests/`.

---

## 9. Not Implemented / External Dependencies

1. **Non-Existent Scope Files:**
   - `onion_routing.py`, `traffic_padding.py`, and `chaff_stream.py` are listed as in-scope files in `docs/audit/PROGRESS.md:31`, but do not exist in the repository filesystem.
2. **External Tor Daemon Required:**
   - The application does not contain an embedded Tor client implementation. Tor connectivity relies entirely on an externally executed Tor daemon listening at `127.0.0.1:9050`.
3. **Pluggable Transport Binaries:**
   - The codebase does not bundle, configure, or execute pluggable transport binaries (e.g. `lyrebird`, `obfs4proxy`). When `P2P_TOR_PT=required`, the code merely greps `/etc/tor/torrc` for configuration directives.
4. **Physical Memory Scan Verification:**
   - The platform-specific methods `_verify_memory_windows` and `_verify_memory_linux` ([anonymous_identity_manager.py:734-775](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L734-L775)) do not inspect physical process RAM. They are stubbed to return `True`. The caller `_verify_memory_scan` explicitly refuses to rely on these stubs and returns `False` ([anonymous_identity_manager.py:721-732](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L721-L732)), making identity rotation disposal verification fail unless an external backend is supplied.

---

## 10. Known Limitations and Residual Risks

1. **Throughput Cap at Fixed Shaper Rate:**
   - Maximum net payload throughput is capped at $24,100\text{ bytes/s} \approx 24.1\text{ KB/s}$. This rate renders the shaped channel impractical for large file transfers (a 50 MB transfer requires ~36.25 minutes).
2. **Operating System Timer Resolution Jitter:**
   - Under heavy CPU load or Windows default timer resolution (~15.6 ms), Python thread sleep intervals (`time.sleep(0.05)`) can drift up to 100 ms, causing `test_constant_rate_intervals` to exhibit timing jitter.
3. **Python In-Memory Key Immutability:**
   - Key material held in immutable Python `bytes` objects cannot be overwritten in memory; `_dod_wipe` can only overwrite `bytearray` buffers. Deallocated `bytes` remain in process virtual memory until reclaimed by CPython memory arenas.

---

## 11. Discrepancies

1. **Missing In-Scope Files (`docs/audit/PROGRESS.md:31` vs Repo):**
   - The audit plan specifies `onion_routing.py`, `traffic_padding.py`, and `chaff_stream.py`. None of these files exist in the repository. Their functionality is partially integrated into `transport_anonymity.py`, `tactical_cloaking_router.py`, and `anonymous_identity_manager.py`.
2. **Cipher Algorithm Discrepancy (`transport_anonymity.py:23` vs `:91-93, 411-436`):**
   - Module header docstring states: `"every wire cell is whitened with AES-256-CTR under a per-session obfuscation key"`. In code, `seal_cell` and `open_cell` instantiate `AESGCM` (AES-256-GCM AEAD) and append a 16-byte authentication tag.
3. **Prohibited Terminology in Source Code:**
   - `anonymous_identity_manager.py:417, 419, 429, 431, 487`: Exception messages include prohibited promotional strings (e.g. `"MILITARY FATAL: ..."`).
   - `transport_anonymity.py:3, 685`: Comments and string constants include prohibited words (e.g. `"TOP SECRET transmission"`, `"DESTROYER-ANON-EPOCH-RATCHET-v2"`).
4. **Disposal Verification Always Fails Without External Backend:**
   - `AnonymousIdentityManager.rotate_identity(..., verify_disposal=True)` raises `IdentityDisposalError` by default because `_verify_memory_scan` explicitly returns `False` when `_memory_manager` lacks `verify_wipe` ([anonymous_identity_manager.py:721-732](file:///d:/code/Main_projects/p2p/p2p_6_1-26/anonymous_identity_manager.py#L721-L732)).

---

## 12. Open Questions for the Author

1. **Scope Realignment:**
   - Should `onion_routing.py`, `traffic_padding.py`, and `chaff_stream.py` be removed from `docs/audit/PROGRESS.md:31` and formalized as features of `transport_anonymity.py` and `tactical_cloaking_router.py`, or are separate modules planned for future extraction?
2. **Cipher Documentation Correction:**
   - Should `transport_anonymity.py:23` be updated to state AES-256-GCM AEAD instead of AES-256-CTR?
3. **Identity Disposal Verification Backend:**
   - Is there an intended native C/Rust backend for `SecureMemoryManager.verify_wipe` to permit `rotate_identity(verify_disposal=True)` to succeed in production without raising `IdentityDisposalError`?
4. **Adaptive Pacing Options:**
   - Is an adaptive cell size/rate configuration planned for high-latency or low-bandwidth environments, or is 50 ms / 1232 bytes permanently frozen for all operational profiles?
