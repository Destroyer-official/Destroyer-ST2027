# Module Audit: messaging_file_transfer

## 1. Overview and Scope
The `messaging_file_transfer` module implements end-to-end user chat, command dispatch, message serialization, multi-device key and message synchronization, ephemeral message lifecycle management, and segmented file sharing across peer-to-peer connections.

The module comprises 17 product files totaling 11,160 verified lines of Python code:

| File Name | Lines | Verified Purpose | Primary Classes / Functions |
| :--- | :--- | :--- | :--- |
| `data/__init__.py` | 19 | Package initialization exporting data management interfaces | Package init |
| `data/file_transfer.py` | 645 | Local transfer record storage, progress tracking, and metadata persistence | `FileTransferStore`, `TransferRecord` |
| `data/manager.py` | 45 | Facade combining user management, peer management, and transfer stores | `DataManager` |
| `data/peer_mgmt.py` | 272 | Local peer profile cache, address mappings, and group relationships | `EnhancedPeerManager` (compatibility wrapper) |
| `data/user_mgmt.py` | 602 | Local user profile storage encrypted at rest using AES-256-GCM and SHA3-512 | `EnhancedUserManager`, `[BANNED-PREFIX]Crypto` (discrepancy) |
| `enhanced_peer_manager.py` | 965 | Peer identity, latency monitoring, connection states, and endpoint resolution | `EnhancedPeerManager`, `PeerInfo`, `ConnectionStats` |
| `ephemeral_messaging.py` | 1,716 | Timer-based message expiration, read-once deletion, and multi-pass zeroization | `EphemeralMessageManager`, `EphemeralMessage`, `DeletionSyncManager` |
| `file_transfer.py` | 634 | Active network chunk transfer coordinator with bounded concurrency (max 8) | `FileTransferManager`, `TransferState` |
| `messaging/__init__.py` | 9 | Package initialization exporting messaging interfaces | Package init |
| `messaging/commands.py` | 888 | Chat slash command parser and administrative execution router | `CommandProcessor` |
| `messaging/encryption.py` | 261 | Per-message encryption wrapper routing through Double Ratchet and policy checks | `MessageEncryption`, `CryptographicOperationError` |
| `messaging/handler.py` | 249 | Inbound message router validating sender identity and payload bounds | `MessageHandler` |
| `messaging/manager.py` | 74 | Coordinator linking message handlers, encryption engines, and command routers | `MessagingManager` |
| `multi_device_manager.py` | 1,557 | Multi-device enrollment, ML-DSA-87 signature chain binding, and CRL revocation | `MultiDeviceManager`, `DeviceInfo`, `UserIdentityDevices` |
| `secure_file_sharing.py` | 2,003 | File protocol extensions for Double Ratchet, chunking, and filename sanitation | `SecureFileHandler`, `DoubleRatchetFileExtension`, `_sanitize_transfer_filename` |
| `secure_file_transfer.py` | 541 | 64KB chunk transfer engine with per-chunk HMAC-SHA384 and root digest validation | `SecureFileTransfer`, `SecureChunk`, `ChunkIntegrityViolation` |
| `secure_message_serializer.py` | 680 | Structured binary wire serializer with MAC-first verification and AEAD framing | `SecureMessageSerializer`, `SecureMessage`, `IntegrityViolation` |

---

## 2. Architecture and Subsystem Mechanics

### 2.1 Wire Serialization and MAC-First Framing
In `secure_message_serializer.py:8-18,87-140`, structured messages follow a strict binary wire layout:
- **Header Structure (56 bytes, big-endian format `>BBHIQQ32s`):**
  - Protocol version: 1 byte (`PROTOCOL_VERSION = 1`).
  - Message type: 1 byte (`MessageType` enum: `HANDSHAKE=0x01`, `DATA=0x02`, `ACK=0x03`, `KEY_ROTATION=0x04`, `HEARTBEAT=0x05`, `FILE_TRANSFER=0x06`, `CLOSE=0x07`).
  - Message flags: 2 bytes (`MessageFlags`: `ENCRYPTED=0x0001`, `COMPRESSED=0x0002`, `URGENT=0x0004`, `REQUIRES_ACK=0x0008`, `FRAGMENTED=0x0010`).
  - Total length: 4 bytes (uint32).
  - Sequence number: 8 bytes (uint64 monotonic counter).
  - Timestamp: 8 bytes (uint64 microsecond Unix epoch).
  - Sender ID: 32 bytes (SHA3-256 digest of sender identity key).
- **Payload & Authentication Tag:**
  - Payload: variable length byte sequence.
  - MAC tag: 32 bytes (HMAC-SHA384 truncated to 256 bits).
- **MAC-First Verification (`secure_message_serializer.py:270-285`):**
  - The trailing 32 bytes of the incoming byte stream are extracted as the expected MAC.
  - HMAC-SHA384 is computed over the preceding data (header + payload) and compared using constant-time `hmac.compare_digest`.
  - If the tag does not match, `IntegrityViolation` is raised immediately. The serializer drops the frame without parsing or exposing payload contents to higher application layers.
- **Production AEAD Metadata Protection (`secure_message_serializer.py:220-222`):**
  - When running in production (`is_production()` or `P2P_ENV=production`), serialization requires an `aead_key`. Omitting this key raises a `ValueError` because plain unencrypted headers would leak sequence numbers and sender IDs to network observers.

### 2.2 Inbound Message Routing and Anti-Spoofing Checks
In `messaging/handler.py:28-100`:
- **Sender Verification:** `MessageHandler.handle_message` inspects the sender field in incoming `MSG:<sender>:<content>` payloads. Line 88 strictly checks: `if orchestrator.peer_username and sender != orchestrator.peer_username`. If the inner sender string differs from the authenticated session peer name, the message is dropped and logged as a security alert (`messaging/handler.py:89`).
- **Sender String Formatting:** Sender names must match `^[a-zA-Z0-9_-]{1,64}$` (`messaging/handler.py:73`).
- **Content Size Ceiling:** Content length is capped at 64KB (`MAX_MESSAGE_PAYLOAD = 65536`). Oversized messages are dropped before application presentation (`messaging/handler.py:84-86`).

### 2.3 Segmented File Transfer and Filename Traversal Defenses
The module provides segmented file transport across three layers (`file_transfer.py`, `secure_file_transfer.py`, `secure_file_sharing.py`):
1. **Filename Sanitization (`secure_file_sharing.py:120-138`):**
   - Function `_sanitize_transfer_filename` strips all directory traversal markers (`../`, `..\`, absolute drive roots).
   - Character whitelist: `[a-zA-Z0-9.-_]`. Forbidden characters are replaced by underscores.
   - Leading periods are stripped to prevent hidden file creation.
   - Path length is capped at 255 characters.
2. **Chunk Framing and Authentication (`secure_file_transfer.py:49-73`):**
   - Files are partitioned into discrete 64KB chunks (`CHUNK_SIZE = 64 * 1024`).
   - Each `SecureChunk` carries a 48-byte HMAC-SHA384 tag computed over `file_id || chunk_number || is_final || data_len || chunk_data`.
   - `verify_hmac` verifies the tag prior to temporary file spooling; any corruption raises `ChunkIntegrityViolation` (`secure_file_transfer.py:91-105`).
   - Upon completing all chunks, SHA3-512 is computed over the assembled file and compared against the manifest digest. Mismatches raise `FileIntegrityViolation` (`secure_file_transfer.py:150-180`).
3. **Concurrency Limiting (`file_transfer.py:92`):**
   - Enforces `self._max_active_file_transfers = 8` concurrent transfer sessions to prevent resource exhaustion and file descriptor starvation.

### 2.4 Ephemeral Messaging and Secure Deletion
In `ephemeral_messaging.py`:
- **Configurable Lifetimes:** `MIN_TTL_SECONDS = 60` (1 minute), `MAX_TTL_SECONDS = 2592000` (30 days), `DEFAULT_TTL_SECONDS = 86400` (24 hours) (`ephemeral_messaging.py:106-108`).
- **Read-Once Operation:** Messages configured with `MessageType.READ_ONCE` trigger immediate zeroization upon their first read access (`ephemeral_messaging.py:72`).
- **Background Purging:** `EphemeralMessageManager.start_expiry_checker()` runs a background thread checking every 60 seconds (`expiry_check_interval = 60.0`) to sanitize expired messages (`ephemeral_messaging.py:459-490`).
- **Memory Zeroization:** Message content is held in mutable `bytearray` objects (`ephemeral_messaging.py:115`). When deleted, content is overwritten with multi-pass zeroization patterns (`ephemeral_messaging.py:380-395`).
- **Deletion Synchronization:** Generates a cryptographic deletion receipt (`hashlib.sha3_256(f"{message_id}:{deletion_time}:deleted".encode()).digest()`) and propagates `DeletionRecord` structures across paired peer devices (`ephemeral_messaging.py:401-403`).

### 2.5 Multi-Device Identity and Signature Binding
In `multi_device_manager.py`:
- **Identity Binding via ML-DSA-87:** Devices are enrolled using post-quantum digital signatures (`LibOQS_MLDSA_87`). Secondary devices must be authorized by an active device, producing a signed `DeviceInfo` structure that tracks `authorizing_device_id` and `signature_chain_depth` (`multi_device_manager.py:83-94`).
- **Device Count Ceiling:** Enforces a maximum limit of 5 active devices per user identity (`DeviceLimitExceededError` raised on 6th enrollment attempt) (`multi_device_manager.py:60`).
- **Device Revocation:** Supports device revocation with signed Certificate Revocation List (CRL) exports (`export_crl_bundle`, `import_crl_bundle`), invalidating revoked public keys across the device mesh (`multi_device_manager.py:12,103-104`).

### 2.6 Command Dispatch and Administrative Router
In `messaging/commands.py:27-219`:
- `CommandProcessor` intercepts slash commands entered in chat sessions:
  - Security administration: `/tier` (operational tier transition and downgrade prevention), `/safety-number` (TOFU 48-digit safety comparison), `/quarantine` (Active Cyber Defense peer quarantine).
  - Identity management: `/identity`, `/rotate` (ephemeral key rotation).
  - Datalink telemetry: `/status`, `/transfers`, `/rekey`, `/spqr`, `/rum-consensus`, `/tfc-status`, `/zgdp`, `/attest`.
  - Datalink control: `/sendfile <path>`, `/silence` / `/cloak` (tactical background chaff toggle), `/exit`.

---

## 3. Interfaces and Public API Surface

### 3.1 `SecureMessageSerializer` (`secure_message_serializer.py`)
- `serialize(message: SecureMessage, aead_key: Optional[bytes] = None) -> bytes`: Serializes message into framed wire binary with appended MAC tag.
- `deserialize(data: bytes, aead_key: Optional[bytes] = None) -> SecureMessage`: Verifies MAC tag first, verifies monotonic sequence, and unpacks payload.
- `serialize_aead_envelope(...) -> bytes`: Wraps message payload, sequence, and sender ID inside AES-256-GCM ciphertext.
- `deserialize_aead_envelope(data: bytes, aead_key: bytes) -> SecureMessage`: Decrypts and authenticates metadata-hiding envelope.

### 3.2 `SecureFileTransfer` (`secure_file_transfer.py`)
- `create_chunks(file_path: Path, hmac_key: bytes, file_id: Optional[str] = None) -> List[SecureChunk]`: Partitions file into 64KB authenticated chunks.
- `assemble_file(chunks: List[SecureChunk], output_path: Path, expected_hash: bytes, hmac_key: bytes) -> bool`: Verifies chunk MACs and root SHA3-512 digest, writing file to disk.

### 3.3 `EphemeralMessageManager` (`ephemeral_messaging.py`)
- `create_message(content: bytes, sender_id: str, recipient_id: str, ttl_seconds: Optional[int] = None, message_type: MessageType = MessageType.STANDARD) -> EphemeralMessage`: Creates timed message.
- `create_read_once_message(content: bytes, sender_id: str, recipient_id: str) -> EphemeralMessage`: Creates single-read message.
- `read_message(message_id: str, reader_id: str) -> bytes`: Retrieves message content (triggers deletion if read-once).
- `delete_message(message_id: str) -> bool`: Immediately zeroizes and removes message.

### 3.4 `MultiDeviceManager` (`multi_device_manager.py`)
- `enroll_device(user_id: str, device_name: str, device_type: str, authorizing_device_id: str, private_key: bytes) -> DeviceInfo`: Enrolls new device up to 5-device limit.
- `revoke_device(user_id: str, device_id: str, reason: str, revoking_device_id: str, private_key: bytes) -> bool`: Revokes secondary device.

---

## 4. Test Evidence and Verification Results

### 4.1 Passing Test Suites
Audit verification executed the following test suites directly verifying messaging and file transfer behaviors:

1. **Messaging Security and Traversal Guards:**
   - Command: `pytest tests/test_file_receive_traversal_guard.py tests/test_parser_fuzz_gates.py tests/test_profile_encryption_lifecycle.py tests/test_production_tier4_tactical_commands.py -q`
   - Result: 56 passed, 3 skipped in 13.85s.
   - Verified behaviors:
     - Neutralization of directory traversal characters in received filenames (`test_file_receive_traversal_guard.py`).
     - Fuzz testing against parser boundaries and corrupted framing headers (`test_parser_fuzz_gates.py`).
     - User profile encryption lifecycle using AES-256-GCM and SHA3-512 (`test_profile_encryption_lifecycle.py`).
     - Tactical chat slash commands, security tier transitions, safety number rendering, and downgrade refusals (`test_production_tier4_tactical_commands.py`).
2. **Defensive NC3 and Remediation Suites:**
   - Command: `pytest tests/test_defensive_nc3_audit.py tests/test_security_audit_remediations.py -q`
   - Verified behaviors:
     - Pre-auth frame ceiling rejection for frames > 64KB (`test_preauth_frame_ceiling_rejects_oversized_frame`).
     - Replay journal persistence and monotonic sequence enforcement.
     - Keystore encryption and message encryption exceptions.

---

## 5. Discrepancies, Limitations, and Technical Debt

1. **Promotional Terminology in Code Identifiers:**
   - `data/user_mgmt.py:42`: Class defined as `class [BANNED-PREFIX]Crypto:` containing helper methods for SHA3-512 username and salt hashing. This violates repository naming guidelines prohibiting promotional terms in source identifiers. Cataloged for `docs/audit/discrepancies.md`.
2. **Promotional Command Syntax:**
   - `messaging/commands.py:135`: Command router accepts `[BANNED-COMMAND-ALIAS]` as an alias for `/eam`.
   - `messaging/commands.py:215`: Help text documents `/cot` as emitting a promotional operational event.
   - Cataloged for `docs/audit/discrepancies.md`.
3. **Duplication of File Transfer Logic:**
   - File transfer implementations exist across four separate files with overlapping responsibilities:
     - `file_transfer.py` (634 lines): High-level async transfer coordinator.
     - `data/file_transfer.py` (645 lines): Progress store and transfer records.
     - `secure_file_transfer.py` (541 lines): 64KB chunking with HMAC-SHA384 and SHA3-512.
     - `secure_file_sharing.py` (2,003 lines): Double Ratchet file extensions and AES-256-GCM chunking.
   - These modules duplicate chunking calculations and transfer state tracking without a unified data plane.