# Module: `destroyer_node.py` (109→162 lines)

Thin Python session wrapper over the `destroyer_core` native engine.
Owns NO cryptography itself; it translates app bytes ↔ fixed-quantum frames.

## Classes / functions (all verified)

- `class DataPlaneUnavailable(RuntimeError)` — raised when the native module
  cannot be imported. Message includes cause, interpreter path, and `sys.path`
  head (added after a real shadowing failure was diagnosed from this text).
- `class DestroyerNode` — one session endpoint.
  - `__init__(port=51820)` — imports `SecureEngine` lazily so the default
    Python path never pays import/build cost. Raises `DataPlaneUnavailable`.
  - `establish(frame_key, start_seq=None, *, is_initiator)` — binds the
    32-byte PQ-derived frame key; random 64-bit start offset unless given.
    `is_initiator` MUST differ per side (nonce-domain separation; simultaneous
    traffic would otherwise reuse nonces — proven by test).
  - `transmit(message, chaff=False) -> bytes` — one fixed-quantum frame.
  - `transmit_large(message) -> list` — 1205B splits; every wire frame keeps
    quantum shape regardless of total size.
  - `receive(frame)` — `(ftype, payload)` or None (silent drop). Never signals.
  - `receive_many(frames) -> bytes` — ordered reassembly; ANY bad chunk raises
    `ValueError` (partial file data is never returned).
  - `seal_stream(data) -> bytes` — 4B-length-prefixed frame stream for the
    `_encrypt_message` outer envelope.
  - `open_stream(blob)` — inverse; None on any defect (fail closed).
  - `drops` — native drop counter passthrough.
- `data_plane_enabled() -> bool` — true only if `P2P_DATA_PLANE=rust`.

## Verified behaviors (executed)

Bidirectional 30-msg both-directions traffic, 100KB file (85 frames) exact
reassembly, tampered-chunk loud abort, wrong-key silence, quanta 256/512/1232
all observed on wire.
