# Module: `p2p_core.py` (2343 lines) — transport + connection lifecycle

IPv6-first direct transport. TCP framed sockets; STUN present but DISABLED by
default (`DEFAULT_STUN_SERVER=""`, `:215-216`; `config.json: stun_servers: []`).

## Classes / functions (signatures verified)

- `class NISTLevel5PolicyEngine` — local allow-list consulted by transport
  (`validate_algorithm`, `reject_weak_algorithm`, `:64-85`).
- `class StunClient` — RFC 5389 `BINDING_REQUEST`/`XOR-MAPPED-ADDRESS`
  (`create_stun_message`, `parse_stun_response`, `get_public_endpoint`,
  `:221-366`). Dormant unless configured; Google/Cloudflare leaks eliminated
  by the empty default.
- `class MessageType` — `USERNAME/MSG/EXIT/HEARTBEAT/...` (`:543`).
- `class Message` — validated `type/sender/content/timestamp` named tuple
  (`__str__`, `_validate`, `parse`, `create_error`, `:584-734`).
- `class FramedSocket` — 4B big-endian length-prefix framing over TCP
  (`is_ssl_socket`, `recv_exact`, `send_framed`, `receive_framed`,
  `:749-973`). 4MB absolute abort ceiling (`MAX_FRAME_SIZE`, `:1140`).
- `class SimpleP2PChat` — connection owner (`:1059`):
  - `__init__` — sockets, tasks, queues, history, `data_plane` flag
    (`P2P_DATA_PLANE`, default `python`), lazy `_rust_engine`.
  - `_get_rust_engine()` / `rust_data_plane_active()` (`:1152-1170`) —
    explicit build error naming `rust_data_plane/` (renamed after a real
    source-dir shadowing failure).
  - `_close_connection`, `_async_input`, `_process_message`,
    `_receive_messages`, `_send_message`, `_send_heartbeats`,
    `_connect_to_peer`, `_chat_session`, `_handle_command`,
    `handle_connections`, `_print_banner`, `_refresh_stun`, `_start_client`,
    `_start_server`, `start`.

## Security properties (verified)

No plaintext negotiation except TLS itself; framing limits bound memory-DoS;
STUN metadata leak removed by default; Rust path strictly opt-in.
