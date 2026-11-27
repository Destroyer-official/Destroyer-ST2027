# Module: `file_transfer.py` (+ `data/file_transfer.py`,
`secure_file_sharing.py`, `secure_file_transfer.py` — one pipeline)

Offer → accept/reject → chunks → complete, all inside the ratchet stream
(plus optional Rust outer envelope via the message path — no separate file
key needed; chunk HMACs + whole-file hash provide integrity).

## Native Rust Document Transfer (`doc_transfer.rs` + `/doc` in `cmd_stream_node`)

- Wire envelope: `DOC:<filename>:<sha384_hex>:<base64_content>` verified with constant-time SHA-384 (`unpack_and_verify_document`) and strict ASCII `[A-Za-z0-9._-]+` filename checks (`doc_seal` / `doc_open`).
- Stream & Tor carriage: `--doc <path>` / stdin `/doc <path>` chunks payloads into `FTYPE_DOC` (`0x08`) frames quantized inside `496B`/`994B`/`1232B` cells (`MAX_STREAM_DOC_BYTES = 256 KiB`), verifies Zero-Trust ingress, and writes to `--recv-dir <dir>` exclusively via non-overwriting `create_new(true)` into non-symlink directories (`memory-only` under `--zero-footprint` when omitted).

## `FileTransferManager` (verified)

`send_file`, `receive_file`, `handle_file_message/chunk`,
`_handle_file_offer/accept/reject/complete/error/cancel`,
`_start_file_transfer`, `_complete_file_reception`, `_send_file_message/error`.

## Verified security properties

- Reception (`_complete_file_reception`): `basename` + charset filter +
  `resolve()` + `is_relative_to` containment + uniquefying — traversal-safe
  in all three stacks (verified by grep: zero raw
  `downloads_dir/metadata.filename` writes remain).
- 10MB cap, per-chunk HMAC, whole-file hash verify before completion,
  MIME/extension screening (not a malware sandbox — documented limit).

## `messaging/` (verified)

- `handler.py: MessageHandler.handle_message / route_message /
  process_incoming_message` — post-decryption dispatch only.
- `encryption.py` — ratchet encrypt/decrypt with optional binding prefix;
  "fallback" labels mean ratchet-without-binding, still L5, never plaintext.
- `commands.py`, `manager.py` — CLI dispatch, session glue.