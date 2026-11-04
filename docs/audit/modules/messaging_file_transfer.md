# Module Documentation: messaging_file_transfer

## 1. Purpose
The `messaging_file_transfer` module implements end-to-end user chat, message serialization, command routing, multi-device cryptographic key synchronization, ephemeral message lifecycle management, and segmented file sharing (`secure_message_serializer.py:1-680`, `file_transfer.py:1-634`, `ephemeral_messaging.py:1-1716`). It protects chat payloads and file chunks with MAC-first verification and directory traversal defenses (`secure_file_sharing.py:120-138`).

## 2. Public Interface

### 2.1 Classes and Key Methods

#### `secure_message_serializer.SecureMessageSerializer` (`secure_message_serializer.py:85-320`)
- `serialize(message: SecureMessage, aead_key: Optional[bytes] = None) -> bytes`: Encodes structured message into wire frame (`secure_message_serializer.py:110-165`). Appends 32-byte HMAC-SHA384 tag. In production, parameter `aead_key` is mandatory (32 bytes); raises `ValueError` if omitted (`:220-222`).
- `deserialize(data: bytes, aead_key: Optional[bytes] = None) -> SecureMessage`: Verifies 32-byte MAC tag using constant-time comparison before unpacking header and payload (`secure_message_serializer.py:270-310`). Raises `IntegrityViolation` if MAC verification fails (`:280`).
- `serialize_aead_envelope(message: SecureMessage, aead_key: bytes) -> bytes`: Encrypts sequence number, sender ID, and payload inside AES-256-GCM ciphertext (`secure_message_serializer.py:170-215`).

#### `secure_file_transfer.SecureFileTransfer` (`secure_file_transfer.py:45-210`)
- `create_chunks(file_path: Path, hmac_key: bytes, file_id: Optional[str] = None) -> List[SecureChunk]`: Partitions file on disk into 64KB chunks (`secure_file_transfer.py:50-85`). Computes per-chunk HMAC-SHA384 tag and returns list of `SecureChunk` objects.
- `assemble_file(chunks: List[SecureChunk], output_path: Path, expected_hash: bytes, hmac_key: bytes) -> bool`: Validates individual chunk HMAC tags, writes chunks to `output_path`, and verifies final SHA3-512 digest against `expected_hash` (`secure_file_transfer.py:90-165`). Raises `ChunkIntegrityViolation` or `FileIntegrityViolation` on mismatch (`:105, 155`).

#### `ephemeral_messaging.EphemeralMessageManager` (`ephemeral_messaging.py:95-320`)
- `create_message(content: bytes, sender_id: str, recipient_id: str, ttl_seconds: Optional[int] = None, message_type: MessageType = MessageType.STANDARD) -> EphemeralMessage`: Allocates timed message (`ephemeral_messaging.py:110-150`). Stores content in mutable `bytearray` (`:115`).
- `read_message(message_id: str, reader_id: str) -> bytes`: Retrieves message content (`ephemeral_messaging.py:190-230`). If message is `MessageType.READ_ONCE`, triggers immediate memory zeroization (`:210`).
- `delete_message(message_id: str) -> bool`: Executes multi-pass zeroization over message memory, issues cryptographic deletion receipt, and notifies peer devices (`ephemeral_messaging.py:380-410`).

#### `multi_device_manager.MultiDeviceManager` (`multi_device_manager.py:75-240`)
- `enroll_device(user_id: str, device_name: str, device_type: str, authorizing_device_id: str, private_key: bytes) -> DeviceInfo`: Enrolls secondary device using ML-DSA-87 signatures up to 5-device limit (`multi_device_manager.py:85-130`). Raises `DeviceLimitExceededError` on 6th attempt (`:95`).
- `revoke_device(user_id: str, device_id: str, reason: str, revoking_device_id: str, private_key: bytes) -> bool`: Revokes enrolled device and updates local Certificate Revocation List (CRL) (`multi_device_manager.py:140-185`).

#### `messaging.handler.MessageHandler` (`messaging/handler.py:28-120`)
- `handle_message(raw_payload: str, orchestrator: Any) -> bool`: Inspects sender and payload bounds (`messaging/handler.py:35-105`). Enforces sender regex `^[a-zA-Z0-9_-]{1,64}$` and drops messages exceeding `MAX_MESSAGE_PAYLOAD = 65536` bytes (`:73, 85`).

## 3. Data Formats and Byte Layouts

### 3.1 Binary Wire Header Layout (`secure_message_serializer.py:8-18, 87-140`)
Messages are framed using a 56-byte header formatted in network big-endian order (`>BBHIQQ32s`):
- Protocol version: 1 byte (`PROTOCOL_VERSION = 1`) at offset 0.
- Message type: 1 byte (`MessageType` enum) at offset 1.
- Message flags: 2 bytes uint16 (`MessageFlags` bitfield) at offset 2.
- Total length: 4 bytes uint32 at offset 4.
- Sequence number: 8 bytes uint64 monotonic counter at offset 8.
- Timestamp: 8 bytes uint64 microsecond Unix timestamp at offset 16.
- Sender ID: 32 bytes (SHA3-256 digest of sender identity key) at offset 24.
- Arithmetic Verification:
  - Header sum: $1 + 1 + 2 + 4 + 8 + 8 + 32 = 56$ bytes (`secure_message_serializer.py:18`).
  - Payload: Variable length $N$ bytes at offset 56.
  - MAC tag: 32 bytes (HMAC-SHA384 truncated to 256 bits) at offset $56 + N$.
  - Total frame length: $56 + N + 32 = N + 88$ bytes. Sum matches code arithmetic.

### 3.2 File Transfer Chunk Layout (`secure_file_transfer.py:49-73`)
- Chunk payload: Up to 65,536 bytes (64 KB) (`CHUNK_SIZE = 64 * 1024`).
- Chunk tag: 48 bytes HMAC-SHA384 over `file_id || chunk_number || is_final || data_len || chunk_data`.

## 4. Algorithms and Pinned Libraries
- HMAC-SHA384: IETF RFC 2104 / RFC 5869. Message authentication tags provided by standard library `hmac` and `hashlib.sha384` (`secure_message_serializer.py:25-30`).
- AES-256-GCM: NIST SP 800-38D. Metadata protection envelope provided by `cryptography.hazmat.primitives.ciphers.aead.AESGCM` (`secure_message_serializer.py:220`).
- SHA3-512: NIST FIPS 202. Full-file assembly integrity digest provided by `hashlib.sha3_512` (`secure_file_transfer.py:150`).
- ML-DSA-87: NIST FIPS 204. Multi-device authorization signatures provided by `oqs.dll` version 0.16.0 (`multi_device_manager.py:83`).

## 5. Dependencies and Hardware Requirements
- Python libraries: `cryptography>=42.0.0` for AESGCM (`requirements.txt`).
- Operating System APIs: Native filesystem operations (`os`, `pathlib.Path`) with POSIX permission checks (0600 file modes) (`secure_file_sharing.py:145`).

## 6. Failure Behavior
- MAC authentication mismatch raises `IntegrityViolation` and drops frame immediately without parsing payload (`secure_message_serializer.py:280`).
- Oversized message (> 64KB) is dropped silently at handler boundary and logged (`messaging/handler.py:86`).
- File chunk MAC mismatch raises `ChunkIntegrityViolation` (`secure_file_transfer.py:105`).
- Final assembled file hash mismatch raises `FileIntegrityViolation` and deletes temporary chunk files (`secure_file_transfer.py:155-160`).
- Device enrollment limit exceeded (> 5 devices) raises `DeviceLimitExceededError` (`multi_device_manager.py:95`).

## 7. Configuration and Environment Variables
- `P2P_MAX_ACTIVE_TRANSFERS`: Maximum concurrent file transfers. Default: `8` (`file_transfer.py:92`).
- `P2P_EPHEMERAL_DEFAULT_TTL`: Default message retention time in seconds. Default: `86400` (24 hours) (`ephemeral_messaging.py:108`).
- `P2P_CHUNK_SIZE_BYTES`: Segmented file transfer chunk size. Default: `65536` (64 KB) (`secure_file_transfer.py:49`).

## 8. Tests Covered and Not Covered
- Covered by Automated Tests:
  - Traversal character stripping in received filenames: verified in `tests/test_file_receive_traversal_guard.py` (12 tests).
  - MAC-first serialization and fuzz bounds: verified in `tests/test_parser_fuzz_gates.py` (16 tests).
  - Pre-auth frame ceiling rejection (> 64KB): verified in `tests/test_defensive_nc3_audit.py` (`test_preauth_frame_ceiling_rejects_oversized_frame`).
  - Tactical chat slash command router: verified in `tests/test_production_tier4_tactical_commands.py` (20 tests).
- NOT Covered:
  - Resumption of interrupted transfers across full operating system reboots.
  - Simultaneous multi-peer file streaming exceeding 100 concurrent nodes.

## 9. Not Implemented / External Dependencies
- Multi-Device Push Notifications: Device synchronization relies on active peer TCP/UDP connectivity; third-party push notification services (APNs, FCM) are not implemented.

## 10. Known Limitations and Residual Risks
- Quadruplicate Transfer Implementation: File transfer is duplicated across `file_transfer.py`, `data/file_transfer.py`, `secure_file_transfer.py`, and `secure_file_sharing.py`.
- Disk Space Exhaustion: Concurrent large file transfers can fill available disk storage if quotas are not configured at the host OS level.

## 11. Discrepancies
- Promotional identifiers in code: `data/user_mgmt.py:42` declares class `[BANNED-PREFIX]Crypto`, and `messaging/commands.py:135` accepts promotional command aliases. Recorded in `docs/audit/discrepancies.md`.

## 12. Open Questions for the Author
- Should `secure_file_transfer.py` and `secure_file_sharing.py` be merged into a single transfer engine?
