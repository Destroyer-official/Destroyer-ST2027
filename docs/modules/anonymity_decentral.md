# Network-anonymity + decentralization modules (verified maps, honest scope)

These modules are REAL implementations but mostly OPT-IN / unwired from the
default direct-TCP hot path (verified: hot path is `p2p_core.py` TCP +
`secure_p2p.py` orchestration). Each states its own activation conditions.

## `metadata_resistance.py`

Padding engine, jitter engine, cover-traffic generator, Tor SOCKS5 proxy
plumbing, manager. Tor path exists; default route is direct (documented
trade-off: latency vs anonymity).

## `covert_channel_defense.py`

Packet normalizer, fixed-rate transmitter, cover injector, detector.
Fixed-rate mode is the strongest timing defense and the most expensive.

## `network_adversary_resistance.py`

Constant-rate engine, onion layers/encryption, relay nodes, multi-hop router,
traffic shaping, multi-path manager (HKDF-SHA512 keys — verified upgraded).

## `decentralized_architecture.py`

DHT (KBucket/routing/storage), mesh discovery, relay nodes, device-sync
transports. `check_hostname=False` instance is CERT_REQUIRED + SHA384
fingerprint-pinned (verified) inside this optional module.

## Operational rule

For cross-country links under nation-state observation, enable ONE of:
private APN (preferred), Tor carriage, or constant-rate cover — direct mode
alone leaks IP/timing metadata by design (no code can hide the peer address
from the peer).
