# Module: `file_transfer.py` (+ `data/file_transfer.py`,
`secure_file_sharing.py`, `secure_file_transfer.py` — one pipeline)

Offer → accept/reject → chunks → complete, all inside the ratchet stream
(plus optional Rust outer envelope via the message path — no separate file
key needed; chunk HMACs + whole-file hash provide integrity).

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
