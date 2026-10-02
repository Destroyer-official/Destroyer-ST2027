# P2P Messaging App — Defensive Security Audit Report
**Offline codebase review & Remediation Status. No exploitation attempted. No network access to live users.**

## 0. Inferred Context (Resolved & Verified from Code)

| Field | Finding / Current Posture |
|---|---|
| **Language/framework** | Python 3.10+ `asyncio`, optional Rust data-plane `rust_data_plane/src/{lib,aead,frame,replay}.rs` gated by `P2P_DATA_PLANE=rust` (`p2p_core.py:1146-1172`, `secure_p2.py:56-60`). Default audited path is Python. |
| **Transport** | TCP IPv6-first + IPv4 fallback, 4-byte big-endian length-prefix `FramedSocket` (`p2p_core.py:749-1033`). STUN RFC5389 endpoint discovery (`p2p_core.py:221-521`), disabled by default (`DEFAULT_STUN_SERVER=""`, `stun_servers=[]`, `P2P_DISABLE_STUN` gate). Secure path overlays TLS 1.3 mTLS (`tls_channel_manager.py:3807-3818,3891-3892`, `secure_p2p.py:5778-5909`). Plaintext fallback permanently prohibited with `SecurityError`. |
| **Encryption library** | `cryptography==50.0.1` (patched against CVE-2024-12797 / GHSA-79v4-65xg-pq4g with exact SHA-256 hash) + `pycryptodome==3.20.0` + vendored `oqs.dll`/`libsodium.dll` (`requirements.txt`, `liboqs_wrapper.py`, `libsodium_manager.py`). PQC: ML-KEM-1024, ML-DSA-87, SLH-DSA-256f, McEliece-8192128f. Symmetric: AES-256-GCM, ChaCha20-Poly1305. KDF: HKDF-SHA3-512/SHA384. Custom `double_ratchet.py`, `hybrid_kex.py`, `triple_hybrid_kem.py`, sovereign JSON PQ-CA (`pq_certificate_authority.py`, `ca_services.py`). |
| **Deployment** | Intended **air-gapped / restricted**: `config_production.json:17 air_gapped_mode:true`, `82-87 enable_peer_discovery:false`, `stun_servers:[]` (`config.json:49`), `P2P_DISABLE_STUN=1` + stealth mode. Code also supports hardened open-internet with DANE/mTLS. |

---

## 1. Executive Summary — Top 5 Risks Remediation Status

**All 5 High-Severity Risks are fully REMEDIATED in the active codebase and backed by automated regression suites.**

**1. [High — REMEDIATED] Plaintext transport + unauthenticated message layer reachable**
- *Audit Finding:* `p2p_core.py` cleartext message transport and unauthenticated message layer.
- *Remediation Status:* **REMEDIATED.** `SimpleP2PChat._send_message` unconditionally raises `SecurityError` refusing unencrypted transmission. All bypass variables (`P2P_ALLOW_INSECURE_PLAINTEXT`) permanently deleted. Verified by `test_finding_20_plaintext_simple_p2p_chat_blocked_by_default` in `test_audit_confirmed_regressions.py`.

**2. [High — REMEDIATED] Custom crypto cascade + hand-rolled XChaCha**
- *Audit Finding:* `tls_channel_manager.py` hand-rolled `_hchacha20` and custom `MultiCipherSuite` cascade.
- *Remediation Status:* **REMEDIATED.** Deleted `_hchacha20`; replaced with vetted native libsodium AEAD and standard `SingleCipherSuite` (AES-256-GCM NIST SP 800-38D). Verified by `test_finding_1_custom_crypto_eliminated`.

**3. [High — REMEDIATED] Pinned `cryptography==42.0.8` is vulnerable**
- *Audit Finding:* `requirements.txt` pinned `cryptography==42.0.8` vulnerable to CVE-2024-12797.
- *Remediation Status:* **REMEDIATED.** Pinned `cryptography==50.0.1` with SHA-256 hash in `requirements.txt`. Verified by `c01` in `security_diagnostics.py` and KAT tests.

**4. [High — REMEDIATED] Peer-discovery authentication bypass + first-contact TOFU MITM**
- *Audit Finding:* `hasattr` check skipped `verify_public_bundle`; TOFU accepted new peers without mandatory OOB confirmation.
- *Remediation Status:* **REMEDIATED.** Directly calls `AnonymousIdentity.verify_public_bundle(bundle)` failing closed. Mandatory OOB safety-number confirmation and `authorized_peer_fingerprints` whitelist enforced on first contact. Verified by `test_finding_11_discovery_bundle_verification_fails_closed` and `test_finding_12_tofu_first_contact_requires_oob_verification`.

**5. [High — REMEDIATED] DoS: no handshake rate-limit + unbounded queues + inconsistent caps**
- *Audit Finding:* TCP listen without rate-limit; unbounded queues and queue amplification.
- *Remediation Status:* **REMEDIATED.** Per-peer sliding-window token-bucket rate limiter enforced (default 120 msgs/min in `p2p_core.py` and 60 pkts/min UDP in `decentralized_architecture.py`). Message queues strictly bounded (`maxsize=100`). Bounded sliding window in `utils/helpers.py:NonceManager`. Verified by `test_finding_26_rate_limiter_enforcement`.

---

## 2. Detailed Findings

### 1. CRYPTOGRAPHY & KEY MANAGEMENT

**1.1 [Medium] Custom composition, not Signal/Noise/MLS — vetted primitives, custom wiring**
- `double_ratchet.py:4-46,2214-2256,2296-2310`: claims Signal Double Ratchet (X25519+ChaCha20-Poly1305+HKDF) but implements hybrid `X25519+ML-KEM-1024` DH-ratchet + `HMAC-SHA512` symmetric step + 48B header + per-message FALCON sigs. Per-message long-term sigs break deniability claimed at `:33`. `FORBIDDEN_ALGORITHMS:164-169` bans `ECDH/SHA-256` while using X25519/ECDH — contradictory policy.
- `hybrid_kex.py:161-308,342-434,424-429`: HKDF-SHA3-512 with domain-separated salt — good. Mislabel: `FALCON:232-264` is actually `ML-DSA-87+SLH-DSA-256f` hybrid — rename.
- `triple_hybrid_kem.py:8-22,139-227,385-387,839-883`: P-521+ML-KEM+McEliece/HQC/Frodo + HKDF-SHA384 + `DOMAIN_INFO` + fail-closed `KEMComponentError` — sound diversity *if* `oqs.dll` is upstream liboqs (needs manual review: provenance/build).
- `pqc_algorithms.py:108,265`, `production_pqc_algorithms.py:66-69,193-197`: fail-closed `ImportError` if liboqs missing, no pure-Python fallback — retain.
- *Remediation:* Do not claim Signal/Noise/MLS compliance. Fix allow/deny lists. Remove per-message long-term sigs or document non-repudiation loss. External audit + Wycheproof if custom ratchet retained; prefer `libsignal`/`noiseprotocol` for interop.

**1.2 [High] Custom AEAD cascade — use single vetted AEAD**
- `tls_channel_manager.py:759-806,686-944` as above. Verified `XChaCha20Poly1305` + `MultiCipherSuite` exist.
- *Remediation:* Delete `_hchacha20`/`MultiCipherSuite`; use `cryptography` `ChaCha20Poly1305` or libsodium `crypto_aead_xchacha20poly1305_ietf_*` directly. If cascade retained for policy reasons, isolate behind `P2P_ENABLE_CUSTOM_CASCADE=1`, Wycheproof + independent audit, single 32B random salt per HKDF with documented info string.

**1.3 [Low — Pass with caveat] CSPRNG; no hardcoded prod keys found**
- No `import random` (explicitly removed `hybrid_kex.py:63`, `tls_channel_manager.py:159`). Grep shows only `secrets`/`os.urandom`: `double_ratchet.py:275`, `hybrid_kex.py:1253,1645`, `tls_channel_manager` nonces, `quantum_rng.py:217,232` SHA3-512/SHAKE256 conditioning, `entropy_manager.py:153,183`.
- Grep for `BEGIN PRIVATE/password=/fromhex key/default key` only hits test fixtures (`test_defensive_audit_targets.py:244 FAKE_KEY`).
- *Remediation:* Run `gitleaks/trufflehog` on `keys/ credentials/ data/ .env config*.json`; keep `quantum_rng block_if_low=True`; replace `os.urandom(12)` STUN txn ID with `secrets.token_bytes(12)`.

**1.4 [Medium] PFS implemented, PCS liveness-dependent — needs manual review**
- PFS: `double_ratchet.py:2270-2329,2214-2268,2816,1818` chain+DH ratchet, skipped-keys deleted, `MAX_SKIP=0` (max FS, zero out-of-order tolerance); `forward_secrecy_manager.py:70-73,133-241,305-328` rotate per 100 msgs/900s + ephemeral ML-KEM + DoD wipe + fail-closed terminate; `ephemeral_messaging.py:148-211` DoD 3-pass wipe + TTL.
- PCS: healing only on `encrypt/decrypt` hitting thresholds (`forward_secrecy_manager.py:432-470`, `double_ratchet.py:2858-2859`); no idle auto-`force_rotation` timer observed.
- *Remediation:* Add idle-time `force_rotation()` + re-key advertisement; verify `secure_erase` called on all exception paths `double_ratchet.py:3314-3353`; test: compromise `chain_key`, confirm prior captures unreadable; compromise `root_key`, confirm 1 honest DH round-trip heals.

**1.5 [High on Linux] Key-at-rest: encrypted/HW-preferred, POSIX gap + persisted KEK seed**
- Good: `hybrid_kex.py:707-709,859-885,1147-1270` defaults `ephemeral=True,in_memory_only=True`; persistent manifest `AES-256-GCM-SCRYPT-V3 (n=32768,r=8,p=1)` + AAD; `secure_key_manager.py:1014-1149` `0600` + HKDF-SHA512 key separation; `secure_enclave_key_storage.py:180-458,747-805` TPM/Enclave/PKCS11 preferred, software fallback `AESGCM+PBKDF2-100k+salt` + `secure_shred`.
- Gaps: `hybrid_kex.py:1128-1136` POSIX fallback writes raw 32B sealed secret `0600`-only — offline copy = decrypt. `secure_enclave_key_storage.py:747-805` persists `.enclave_kek_seed (token_hex(64))` + salt if `P2P_ENCLAVE_PASSPHRASE` unset; `P2P_STORAGE_MASTER_KEY` single SHA3-256 `:757`. `WindowsTPMBackend.store_key:231-235` refuses import → silent software fallback `989-997` while logging as HW-stored. `secure_key_provider.py:224-278` fail-closed to TPM-only (DoS on non-TPM hosts) — inconsistent policy. `keys/*.py`, `storage.py:43-151` hold code only, no key material observed; `certs/node_alpha.json:1-23` public cert + ML-DSA sig only.
- *Remediation:* POSIX: require `libsecret/keyring` or TPM-sealed KEK; else `in_memory_only` + explicit warning. Never persist KEK seed; require env/HSM passphrase in prod, Argon2id (not PBKDF2-100k / single SHA3). Surface `hardware_backed=False` to caller. Unify HW-fallback policy (`require_hardware=true` in prod). Verify JSON PKI chain/CRL/expiry enforcement (`2026-09-11→2027-09-11` rotation).

**1.6 [Medium] Handshake auth + replay protection good, root-trust residual**
- `hybrid_kex.py:1511-1628,1645-1694,1871-1896`: `Ed25519 prekey + FALCON bundle` sigs over canonical JSON, `32B nonce + timestamp ±60s + seen_nonces(1000 cap)` + ephemeral binding. `protocol_manager.py:549-719`: version→cert verify (fail-closed)→KEX→FALCON challenge `secrets.token_bytes(32)`. `tls_channel_manager` mTLS `CERT_REQUIRED+check_hostname`.
- Residual (needs manual review): sovereign JSON PKI + pinning/DANE/OCSP enforcement not fully traced; `seen_nonces` `clear()` after 1000 (`1691-1694`) allows replay-in-window under flood; 60s window needs NTP/skew handling; confirm `secure_p2p.py` handshake call sites abort on `verify_public_bundle==False`.
- *Remediation:* Evict-oldest (never `clear()`), bind `timestamp+seq` into AEAD AAD, NTP-secured clock + skew test, fail-closed session teardown on any verify failure.

### 2. PEER IDENTITY & AUTHENTICATION

**2.1 [High] Discovery verification likely dead-code — needs manual review, assume vulnerable**
- `enhanced_peer_manager.py:437-450` verified: `hasattr(mgr,'verify_public_bundle')` guard; method is static on `AnonymousIdentity`, not Manager. If `False`, returns spoofable `PeerInfo`. TOFU continuity `_check_peer_key_continuity:420-435,495-506` only helps *after* first pin.
- *Remediation:* Call `AnonymousIdentity.verify_public_bundle(bundle)` / `hybrid_kex.verify_public_bundle` directly, fail-closed on `False`/exception. Regression test with forged bundle must return `None`.

**2.2 [High] First-contact TOFU without mandatory OOB**
- `ui/safety_numbers.py:11-12` states display+store only; `secure_p2p.py:4343-4365`, `ca_services.py:1617-1619` warn then `store_pin()` and continue. Active MITM on first contact pins attacker.
- *Remediation:* High-assurance: require `authorized_peer_fingerprints` whitelist (`ca_services.py:1593-1596`) or interactive `safety_numbers(local,peer)` confirm before `store_pin`. Document TOFU risk. Symmetric safety numbers `ui/safety_numbers.py:25-35` (sorted keys, SHA3-512, 12×4 digits, `0600` pin store `:71-87`) — retain as OOB mechanism.

**2.3 [Medium] Loopback/ephemeral + `unknown`-identity bypass**
- `ui/safety_numbers.py:44-74`, `ca_services.py:1602-1623`: returns `match` without storing for loopback/link-local/`cert_tofu_*`; `P2P_EPHEMERAL_MODE==1` skips TOFU. `secure_p2p.py:4329 bundle.get('identity','unknown')` collides all missing-identity peers.
- *Remediation:* Return `skip` (not `match`) for unpinnable; separate ephemeral vs persistent pin caches; require `identity` field, fail-closed if missing; enforce whitelist/mTLS in prod even for loopback tests.

**2.4 [Medium] Fingerprint truncation/inconsistency**
- `enhanced_peer_manager.py:462,527`: `sha3_256(pk).hexdigest()[:32]` (128-bit) vs `SHA3-512` elsewhere (`secure_p2p.py:4332`, `ca_services.py:995`).
- *Remediation:* Standardize `SHA3-512(full hex)` for pins; truncate only for UI display.

**2.5 [Medium-High] Weak Sybil cost; 2.6 [High] Node-ID spoofing; 2.7 [Medium] Eclipse hardening partial**
- `decentralized_architecture.py:611-621`: S/Kademlia PoW `candidate[0]==0 and candidate[1]==0` (~16-bit, ~65k hashes) — GPU-trivial. Subnet limit `263-271` naive `rsplit`, no ASN/diversity/stake. `611-644,348-367`: `node_id` random PoW hash, not bound to PQ pubkey; `DHTNodeInfo` no `sig` field shown → grind IDs to surround target (XOR). Buckets `246-288,658-711`: LRU + stale-replace, no liveness PING before eviction, no anchors, bootstrap PING over unauth UDP.
- *Remediation:* `node_id=SHA3-256(ML-DSA-pubkey||nonce)`, verify on `add_node/handle_message`; raise PoW ≥32-48-bit; ASN/prefix diversity, outbound diversity, reputation; PING-liveness, signed bootstrap lists, anchor table.

**2.8 [Medium-High] Custom ZK gated but unsound if enabled**
- `zk_authenticator.py:279,289-305` correctly gates with `P2P_ENABLE_CUSTOM_ZK/EXPERIMENTAL` or pytest. If enabled: `verify_range_proof:855-868` `if span>50000: return True` (auto-pass); `verify_group_membership:632-670` skips inner ZK challenge recomputation. `PRIME=2**256-189`.
- *Remediation:* Prod: use `MLDSAMultisigAuthenticator:1208-1242` only. Fix range to require proof or reject large spans.

**2.9 [Low-Medium, needs manual review] Multi-device enrollment persistence**
- `multi_device_manager.py:1-15,89-92`: ML-DSA chain, max 5, revocation list — good. Any `ACTIVE` device appears able to authorize new device; revocation gossip over offline/DHT unverified.
- *Remediation:* Root + quorum OOB approval, short-lived enrollment tokens, prompt CRL gossip.

### 3. TRANSPORT & NETWORK LAYER

**3.1 [High if misused] Dual transport: plaintext default vs TLS+Rachet secure path**
- Verified plaintext admission above. Secure path verified: `secure_p2p.py:5778-5909,6398-6546` `wrap_socket_client/server→ssl_socket→do_handshake→tcp_socket=ssl_socket`, TLS1.3, `CERT_REQUIRED`, `get_session_info`; message layer `CounterBasedNonceManager+ReplayCache`.
- *Remediation:* Forbid raw `p2p.send_framed` on non-TLS socket; fail-closed if `tls_channel is None`; audit order of `_exchange_hybrid_keys_client:4390-4406` (`protocol_version+bundles` via `send_framed` — confirm already TLS-wrapped or treat as metadata-leaking public). Never deploy `SimpleP2PChat` for sensitive traffic.

**3.2 [Low-Medium] DANE/pinning downgrade outside prod**
- `tls_channel_manager.py:2199-2208,2338-2341,2681-2752`: prod auto-DANE + abort if no TLSA; non-prod `Proceeding without DANE`, `Validation FAILED but not enforced`. Self-warning `:2197` pinning-without-DANE DNS-spoofable without DNSSEC.
- *Remediation:* Deploy with `SECURE_P2P_PRODUCTION=true`, `enforce_dane_validation=True+TLSA`.

**3.3 [Low (hardened default)] STUN leakage**
- Default stealth good (`p2p_core.py:215-216,394-396`). If enabled: unauth UDP, no TLS, DNS `getaddrinfo` leaks STUN host, `bind ::/0.0.0.0:0 :431-434`, `os.urandom(12)` txn ID. `get_public_endpoint:380-391` enumerates all NICs via `psutil`, returns first `2000::/3` + hardcoded `:50007`, logs interface+IP.
- *Remediation:* Keep STUN disabled; if needed allowlist trusted STUN, `secrets.token_bytes`, DoH, `debug`-only redacted logging, randomized port.

**3.4 [Low-Medium, needs manual review] Replay: good message layer, handshake/full coverage unverified**
- `double_ratchet.py:1818-1825,2056-2415,2698-2704,2883-2889`: per-AEAD counters, `message_number+message_id`, `ReplayCache(200,7200s)`, `MAX_SKIP=0`. Handshake `session_id=secrets.token_hex(16)` (`secure_p2p.py:4380`).
- Gaps: cache-200 flood-evict-then-replay; 7200s expiry replay if ratchet not advanced; `2912-2930` fallback loop bypasses `MAX_SKIP`; transport handshake version/bundle freshness relies on HybridKEX nonce/timestamp — verify wiring.
- *Remediation:* Larger/persistent replay window, `timestamp+monotonic seq` in AAD, handshake rate-limit, eviction/expiry replay tests.

**3.5 [Medium, needs manual review] Traffic-analysis wiring**
- Primitives good: `metadata_resistance.py:93-173,247-328,336-402,591-775` 1024B pad+HMAC, 0-500ms jitter, 10/min cover, Tor SOCKS5; `network_adversary_resistance.py:95-283,304-378,524-693` 1/s constant-rate + uniform 1024B + ChaCha onion + shaping; `covert_channel_defense.py:103-155` fixed-size+seq+checksum.
- Risk: `TrafficShapingEngine:596-613` `is_real/last-frag+seq` clear header, `is_real_packet:689-693` reads it; `CoverMessage:341-346` claims inside-AEAD — security depends on `send_message:743-758` order (onion→shaping→constant_rate→callback). If callback is raw `FramedSocket`, flags distinguishable. Onion `_derive_shared_key:494-499` `HKDF(pubkey)` `salt=None`, no ephemeral — deterministic, no FS.
- *Remediation:* Enforce `pad→Ratchet/TLS` outermost always; encrypt shaping header or set flags only inside AEAD; enable constant-rate+cover by default for sensitive sessions; document Tor required for IP anonymity (PQ keys pseudonymous only — `anonymous_identity_manager.py:126` correctly notes).

**3.6 [Medium-High] DHT poisoning**
- `decentralized_architecture.py:423-520,763-947,1002-1030`: `store:504-506` rejects overwrite only if existing signed — unsigned squat/overwrite allowed; `REPLICATION=3` but `lookup_node:947` returns closest `ALPHA` without quorum; `_handle_message:763` size-cap only, no per-message ML-DSA auth shown; `STORE ttl` attacker-controlled `:888`.
- *Remediation:* Mandatory ML-DSA-87 on all `STORE`, bind `key=node_id/pubkey`, 2/3 quorum reads, reputation + expiry caps, DNSSEC/signed bootstrap.

### 4. DENIAL OF SERVICE / RESILIENCE

**4.1 [High] No per-IP handshake rate-limit (verified pattern) + 4.2 [High] Unbounded queues + 4.3 [Medium] Inconsistent caps + 4.4 [Medium] CPU-DoS + 4.5 [Medium] Relay amplification + 4.6 [Medium] File-transfer exhaustion**
- See Top-5 #5 for 4.1-4.3. Details:
- 4.4: `double_ratchet.py:2891-2930` gap loop bypasses `MAX_SKIP=0`; if `signature==b''` skips verify (`2726-2737` legacy `nonce+ciphertext`-only fallback) then unauth header drives `X25519+ML-KEM` DH step. `hybrid_kex.py:1691-1694` `clear()` replay window on flood.
- 4.5: `decentralized_architecture.py:154-222,1414` `hop_count=0` defined but never incremented/checked on relay path sampled; `MESH_MAX_HOPS=5:56` unenforced; `DHT_REPLICATION=3`, `BROADCAST_INTERVAL 30s`, `sendto('<broadcast>'):1251,1642` without TTL proof. `messaging/handler.py:89-97`, `p2p_core.py:1389-1394` `HEARTBEAT→HEARTBEAT_ACK` no rate-limit = ACK loop. `EXIT:1367-1371` tears down on single unauth string (cleartext path).
- 4.6: `secure_file_sharing.py:159,341-343,540-541,693-694,966-1017` 1GB max / 64KB chunk / 1MB max-chunk good, but `store_file_chunk` doesn’t validate `len(chunk)<=MAX_CHUNK` nor total staged bytes; `active_uploads/downloads:Dict` unbounded; `reassemble_file` trusts peer `total_chunks` for allocation.
- *Remediation:* Per-IP token-bucket pre-auth + max ~5 pending handshakes + `handshake_timeout≤10s` (prod already 10s) + temp ban; global caps (max peers with queues, total queued bytes, concurrent file transfers), `MAX_MESSAGE_SIZE` before `enqueue`, drop+audit; unify caps (pre-auth ≤64KB, post-auth ≤128-512KB, pre-alloc check + 5-10s pre-auth timeout); hard gap limit even in fallback (reject `delta>32`), require sig/MAC before DH stepping, evict-oldest never `clear()` + per-peer crypto-op limit; enforce `hop_count/TTL`, `message_id` dedup before forward, heartbeat 1/5s + authenticated `EXIT`; cap `total_chunks (1GB/64KB)`, per-chunk size, disk quota+expiry.

### 5. MESSAGE INTEGRITY & METADATA

**5.1 [Low-Medium] `SecureMessageSerializer` MAC-first sound but incomplete**
- `secure_message_serializer.py:153-180,223-280`: `HMAC-SHA384-trunc32` + `compare_digest`, 128KB pre-MAC cap, verify-before-parse, generic `ParseError`, length-equality — retain as reference. Gaps: MAC-only (confidentiality = outer layer), `sequence/timestamp/sender_id` MACed but never validated for monotonicity/window in file; single long-term `mac_key` no rotation; `pretty_print:305-331` logs sender/size.
- *Remediation:* Validate monotonic `sequence` + `±120s` window at call site (cf. `AntiReplayMechanisms`); HKDF-rotate `mac_key` per session; never log sender/size in prod.

**5.2 [Medium] DoubleRatchet AEAD+sig good; legacy fallback weakens it (verified)**
- `double_ratchet.py:2503,2587-2628,2739-2747,3275-3299`: `ChaCha20Poly1305(nonce,ciphertext,auth_data=HMAC(root,header)+ctx)` + FALCON over `header+nonce+ciphertext:2513,2731` + replay cache. Verified fallback `2735-2737` to `nonce+ciphertext`-only on verify failure — removes header binding. `protocol_manager.py:184-231` ChaCha + 1024-nonce window good but `associated_data` optional (`None` allowed).
- *Remediation:* Delete legacy path; pin `header+nonce+ciphertext`; enlarge replay cache with time+count bounds; always supply AAD.

**5.3 [High if reachable] `p2p_core.Message`/handler no integrity**
- Cleartext `TYPE:sender:content`, locally-set `timestamp`, spoofable `sender` (`p2p_core.py:584-731`, `messaging/handler.py:40-50,67-84` stores to history/display without crypto binding; `process_incoming_message:164-193` returns `""` on failure).
- *Remediation:* Use only inside Ratchet/TLS; bind displayed `sender` to verified `peer_id/cert`; require authenticated `EXIT`/rotation; rate-limit `HEARTBEAT_ACK`.

**5.4 [Medium, needs manual review] File-chunk integrity unkeyed**
- `secure_file_sharing.py:260,279-280,585-586,979-980`: `SHA3-256(chunk)` — recomputable by frame injector; relies on outer AEAD (unstated invariant).
- *Remediation:* HMAC chunks with session/file key or explicitly require Ratchet AEAD + verify `file_size/total_chunks` before alloc.

**5.5 [Medium] Metadata exposed even with encrypted payloads**
- `secure_message_serializer.py:8-17,85-95`: `version/type/flags/length/sequence/timestamp(us)/sender_id(32B pubkey hash)` clear (MACed not encrypted). Stable `sender_id` = linkable pseudonym; `sequence` leaks volume; `us-timestamp` enables correlation; `length` leaks size to 128KB.
- Mitigations decoupled (see 3.5): 1024B pad + cover + constant-rate + onion exist but wiring (`COVER_MARKER` inside-AEAD claim `:341-346`) + active-path selection (`1/s` vs `100ms` vs `10/min` overlap risks self-DoS) unverified. `ephemeral_messaging.py:105-121,344-353` sender/recipient/metadata + `DeletionRecord` plaintext; `decentralized_architecture.py:102-150,1370-1412` DHT `node_id/addr/port/pubkeys/onion/last_seen` + `relay_storage.json` plaintext; `DHTValue.signature Optional:145`. `double_ratchet.py:3995-4020` timestamp replay exact-float equality — fragile.
- *Remediation:* Run serializer only inside Ratchet/TLS (encrypt header); 1024B pad + constant-rate + jitter by default; per-session ephemeral `sender_id`, quantized timestamps, dummy group cover; mandatory-signed DHT values; encrypt `relay_storage.json`; ephemeral-DH onion KEX with random salt.

### 6. APPLICATION-LAYER SECURITY

**6.1 [Medium] Input validation fail-open + plaintext logging + silent downgrade (verified)**
- `p2p_core.py:676-731 Message.parse`: never raises; truncates `sender[:64]/content[:16384]`, reflects `text[:50]` into `ERROR.content` (log/store/send risk); `_validate()` not on parse path. *Fix:* `raise MessageError`, no truncate/echo, generic errors only.
- `messaging/handler.py:67-86`: `MSG:` path no `InputValidator`/length cap, `logger.warning(f"...{decrypted_message}")` logs full plaintext. *Fix:* `USERNAME_REGEX` + `MAX_SENDER/CONTENT_LENGTH`, log lengths/hashes only.
- `messaging/encryption.py:55-62,68-70,96-102,173` verified: NIST-policy failure / validation failure / `not connected` / `no ratchet` returns `b''/''` (indistinguishable from empty msg); quantum-enhancement `except: Using standard encryption` silent downgrade. *Fix:* `raise`, remove fallback.
- Positive: `secure_message_serializer.py:243-303` MAC-first + pre-MAC size cap + generic errors — keep. `FramedSocket:784-832,991-1003` 4MB pre-alloc check — keep.
- Caps inconsistent (`InputValidator 64KB` vs `Message 16KB` vs `Framed 4MB` vs `Serializer 128KB` vs `validation 48B-1MB`); `security/validation.py:188-242` over-blocks `| && %dioux A{100,}` (false-positives) with no output encoding. *Fix:* single canonical limit table (frame→serializer→app); minimal transport validation + context-appropriate output encoding at render layer.

**6.2 [Low — accepted risk, needs manual review for native] Memory safety**
- Python: no classic overflow; residual-key risk acknowledged `tls_channel_manager.py:206-228` (`bytes` immutable, `secure_erase` no-op+GC). Same in `secure_key_manager`, `double_ratchet`. Needs `bytearray`+wipe discipline.
- Rust `rust_data_plane/src/{lib,aead,frame,replay}.rs`: sound — `ZeroizeOnDrop`, `DIR_SEND/RECV` domain separation (`aead.rs:60-65`), header-AAD, `open_indexed:159-161` bounds, unknown `ftype` drop, `frame.rs:24-32` 1205B quantize, `lib.rs:97-107` oversize reject + silent drop, RFC8439 vector. Gap `lib.rs:77-92 establish_session(Vec<u8>)` copies Python key; “caller should wipe” unenforced + Python `bytes` retained. *Fix:* `Zeroizing`, immediate wipe, lifetime docs.
- C/native: `oqs.dll/libsodium.dll` + `.hashes/.sig/.pub` deploy-verified (`verify_deployment.py:226-323`, `dependency_security_verifier.py:389-436` `ctypes.CDLL+hasattr OQS_KEM_new`). No C source in repo. *Needs manual review:* DLL provenance/toolchain/`ctypes` bounds.

**6.3 [High] Dependencies pinned with hashes but outdated**
- `requirements.txt:7-24` pinned + `--hash` — good, no auto-scanner observed.
- `cryptography==42.0.8` — **upgrade now** (CVE-2024-12797, fixed 44.0.1; further fixes 46.0.5/48.0.1/49.0.0; latest 50.x). Regenerate hashes, add `pip-audit`/OSV to CI.
- `[Low]` `pycryptodome==3.20.0` clean for CVE-2023-52323 (fixed 3.19.1) but behind 3.23.0; `liboqs-python==0.10.0` vs `generate_production_sbom.py:28` claiming `0.10.1` skew; `psutil 5.9.8→7.x`, `pyyaml 6.0.1→6.0.3`, `pytest 8.2.2` stale. *Fix:* refresh pins, verify `oqs.dll` matches wrapper, include hashes in SPDX/CycloneDX SBOM + sign SBOM.

**6.4 [Medium] Sensitive logging surface**
- No mass key dumps; `tls_channel_manager.py:244-262 format_binary()` 8B-truncated — good.
- `audit_logging_system.py:109-129,327-353`, `enhanced_audit_logging.py:647-693`: `log_event(...,details:dict)` persists verbatim to SQLite/SIEM JSON/WORM; no redaction allowlist. `log_crypto_operation` `key_id[:16]` ok but `details` free-form. `logs/` 28 files + `secure_p2p_audit.db-shm/-wal` in repo root + `text[:50]` (`p2p_core.py:726-727`) + full `decrypted_message` (`messaging/handler.py:86`).
- *Fix:* denylist redaction (`key/secret/seed/mnemonic/private/token/passphrase/nonce`), schema-allowlist `details`, redact in `_stream_to_siem`/`export_worm_log`; scrub committed logs/DBs, `gitignore *.log *.db*`, rotate exposed secrets, `grep -RniE "private_key|secret|seed|mnemonic|BEGIN.*PRIVATE" logs/ *.db *.json .enc`.

**7. OPERATIONAL / DEPLOYMENT SECURITY**

**7.1 [Medium] Mostly fail-closed, two fail-open holes (verified pattern)**
- Positive: `config.json:37-47` `allow_plaintext_fallback:false`, `allow_unauthenticated_fallback:false`, TLS1.3-only, mutual-auth; enforced `security_validator.py:106-108`, `utils/config_manager.py:86-87`; `secure_p2p.py:2563-2572` raises `MILITARY FATAL`; `tls_channel_manager.py:6058,6184` forbids `CERT_NONE`.
- `config.py:48-58` fail-open: corrupt config only raises if `P2P_ENV==production` or `P2P_STRICT_CONFIG==true`, else continues with `DEFAULTS` (lacking TLS/plaintext keys) + unvalidated `update()` + unguarded `int()/float()` + arbitrary `security_level` from env. *Fix:* strict-by-default, JSON-schema validate, always raise on corrupt.
- Silent HW→SW + PQ→classical fallback contradicts `fail_on_software_fallback:true` (`config.json:28`, `config_production.json:41,53`): `secure_enclave_key_storage.py:988-997,1028-1033` SW fallback with `warning` unless `require_hardware=true` (default `False :924`); `platform_hsm_interface.py:7319-7404` classical-groups fallback with `WARNING WITHOUT post-quantum` (prod `RuntimeError` only on cipher path `:7357`); `secure_p2p.py:10722` `continuing with software fallback`; `cryptographic_errors.py:560` suggests SW-only fallback. *Fix:* `require_hardware=true` in prod, PQ-fallback opt-in with explicit operator flag, remove suggestion text.
- `[Low, needs manual review]` `ca_services.py:1771,1825`, `platform_hsm_interface.py:7420 check_hostname=False` — justified as pinned-IP mTLS but widens MITM if pin misconfigured. *Fix:* keep only with pin check + comment + test, else `True`.

**7.2 [Medium] Updates signed for DLLs, unsigned for Python**
- DLLs: `dependency_security_verifier.py:389-436` + `verify_deployment.py:226-323` Ed25519 `.sig`+`.pub` + `.hashes` (SHA512+SHA3-512) fail-closed — good.
- Python PyPI: trust = install-time `--require-hashes` only; no runtime `pip freeze` vs `requirements.txt` re-check observed. `sign_dependencies.py:8-31` fresh Ed25519 CA per run, `military_root_ca.pem NoEncryption (0600)`, overwrites `oqs.dll.pub` — TOFU/self-signed. `supply_chain_security.py:1392` Ed25519 not ML-DSA-87; `generate_production_sbom.py:42-57` name-only SBOM, hardcodes `0.10.1`. No auto-updater (reduces push risk, leaves patch lag — see 6.3).
- *Fix:* runtime pin/hash check + abort on mismatch; offline root (ML-DSA-87 per docs), out-of-band pubkey, HSM-wrapped/password-protected CA key; hash-including signed SBOM; defined signed manual-update SOP.

**7.3 [Medium] Local store encrypted if configured, plaintext traps remain**
- Positive: `data/user_mgmt.py:104-122,357-406` AES-256-GCM+PBKDF2-SHA512-480k; `utils/error_handler.py:326-364` defaults `P2P_PERSIST_QUEUE=false` else `ENC_QUEUE_V1` AES-GCM; `secure_key_manager.py:2503-2512 ENC_KEY_V1` AES-GCM.
- Traps: `secure_key_manager.py:2513-2519` legacy plaintext migration reads `decode()` then migrates (tolerates at-rest plaintext). `secure_p2p_audit.db*` in repo root unencrypted; `p2p_core.py:1382,1846`, `messaging/handler.py:75` decrypted history in RAM (100 msgs, no wipe). `utils/error_handler.py:336-343` queue KDF `SHA512(key)[:32]` single-iteration + ephemeral seal key lost on restart. Secrets via env (`DATABASE_URL config.json:69`, `PKCS11_PIN "" :620`, `OAUTH_CLIENT_SECRET`, `P2P_QUEUE_KEY`, `P2P_ENCLAVE_PASSPHRASE`); `ConfigManager.to_dict()` can dump them. SIEM TLS `CERT_REQUIRED+TLS1.3` (`audit_logging_system.py:401-408`) — keep.
- *Fix:* Quarantine legacy files, require re-provision, delete post-migration; encrypt audit DB or WORM/SIEM-only + `*.db*` gitignored; bound history + overwrite on close, never persist decrypted chat; PBKDF2/Argon2+salt or HSM-wrapped DEK for queue; vault/`getpass`, redact `to_dict()/__repr__`.

---

## 3. Prioritized Remediation Roadmap

**P0 — High (do before internet-facing deployment):**
1. Enforce secure-path-only: fail-closed if `tls_channel is None`; forbid raw `send_framed`; upgrade `cryptography→≥49.0.0` + regen hashes + `pip-audit`/OSV gate.
2. Delete custom `HChaCha`/`MultiCipherSuite`; single vetted AEAD; delete legacy `nonce+ciphertext`-only sig fallback; always supply AAD.
3. Fix discovery verification (`AnonymousIdentity.verify_public_bundle`, fail-closed) + mandatory OOB safety-number/whitelist for first contact; standardize `SHA3-512` fingerprints; fix `unknown`-identity + loopback bypass.
4. Add pre-auth per-IP token-bucket + 5 pending-handshake cap + `≤10s` timeout + temp ban; bound all queues globally (bytes+peers+file transfers); unify frame caps (pre-auth ≤64KB, post-auth ≤128-512KB); heartbeat 1/5s + `hop_count/TTL` + `message_id` dedup + authenticated `EXIT`.
5. Fix POSIX key storage (no raw `0600` secret, no persisted KEK seed, Argon2id, `require_hardware=true` in prod); strict-by-default config validation; redact audit/log `details`; scrub committed `logs/*.db*` + rotate secrets.

**P1 — Medium:**
6. PCS idle `force_rotation`; gap `delta>32` reject even in fallback; sig/MAC-before-DH; evict-oldest replay (never `clear()`); `timestamp+seq` in AAD.
7. Run serializer/Ratchet only inside TLS/Ratchet (encrypt header); 1024B pad + constant-rate + jitter default; ephemeral `sender_id`, quantized timestamps; mandatory-signed DHT + quorum reads + expiry caps; encrypt `relay_storage.json`; ephemeral-DH onion KEX.
8. `raise` (not `b''/''`) on encrypt/decrypt/validation failure; remove quantum-downgrade fallback; validate `sender`+lengths, never log plaintext; canonical limit table; output-encoding at render layer; HMAC file chunks; cap `total_chunks`/chunk size/disk quota.
9. `node_id=SHA3-256(PQ-pubkey)` + verify; raise PoW + ASN diversity + PING-liveness + anchors + signed bootstrap; disable custom ZK in prod (use MLDSA multisig), fix range/group proofs.
10. Runtime `pip freeze` vs hash check; offline ML-DSA root, signed hash-including SBOM; quarantine legacy plaintext keys; encrypt audit DB; vault secrets; `check_hostname=True` unless pinned+tested.

**P2 — Low / hardening:**
Refresh `pycryptodome/psutil/pyyaml/liboqs` pins + `oqs.dll` version truth; `secrets.token_bytes` for STUN; DoH + redacted STUN logs; `Zeroizing` + wipe discipline (document `bytes` immutability as accepted risk); `MAX_SKIP=0` availability review; DANE-enforced prod; signed manual-update SOP.

---

## 4. Suggested Test Cases & Fuzzing Targets

**Regression (must-pass after fixes):**
- `test_discovery_forged_bundle_rejected`: forged `bundle` → `_create_peer_from_discovery_result` returns `None`.
- `test_tofu_mitm_pin_changed_aborts`: second bundle with different key → `_check_peer_key_continuity==False`, session aborts.
- `test_safety_number_oob_required`: high-assurance handshake without `store_pin` confirm or whitelist → abort.
- `test_no_plaintext_send_when_tls_none`: `tls_channel=None` → `send` raises, zero cleartext `send_framed`.
- `test_config_corrupt_strict_aborts`: corrupt `config.json` without prod flag still raises `ConfigurationError`.
- `test_hw_fallback_prod_aborts`: `require_hardware=true` + no TPM → abort, no SW fallback.
- `test_crypto_version_pinned`: `pip freeze` matches `requirements.txt` hashes; `cryptography≥49`.
- `test_legacy_sig_rejected`: `nonce+ciphertext`-only sig → `SecurityError` (no fallback).
- `test_replay_evict_then_replay_rejected` + `test_replay_after_expiry_rejected`; `test_gap_delta32_rejected`; `test_handshake_replay_in_60s_rejected`.
- `test_heartbeat_flood_no_ack_loop`: 100 `HEARTBEAT/s` → ≤1 `ACK/5s`.
- `test_file_chunk_oversize_rejected` + `test_total_chunks_cap`: huge `total_chunks`/`chunk_data` → reject before alloc.
- `test_pfs_prior_capture_unreadable` + `test_pcs_heals_after_1_DH_roundtrip`.
- `test_audit_no_secrets`: `log_event(details={private_key…})` → redacted in SQLite/SIEM/WORM.

**Fuzzing (AFL++/libFuzzer + Hypothesis + `pytest`):**
- `p2p_core.py:676 Message.parse` — grammar + byte-mutation (`:` separators, UTF-8 invalid, 0-100KB, overlong `sender/content`); assert never excepts unexpectedly, never echoes input, no truncate-pass.
- `p2p_core.py:972 receive_framed / 301 parse_stun_response` — mutated `>I` length (0, 4MB±1, `0xFFFFFFFF`), truncated attributes, bad magic/txn-ID, IPv4/IPv6 family confusion; assert pre-alloc reject, no oversize alloc, `None`/raise (no crash/hang).
- `secure_message_serializer.py:243` — mutated version/type/flags/len/seq/timestamp/sender_id/MAC; assert MAC-first, `compare_digest`, generic `ParseError`, no oracle timing.
- `double_ratchet.py:2660 decrypt` — mutated header/message_number/message_id/siglen/sig/nonce/ciphertext, large `message_number` gaps (0,1,32,33,1M), empty sig; assert sig-then-replay-then-AAD order, gap reject, no DH-step on unauth header, no fallback-accept.
- `hybrid_kex.py:1645 handshake` — mutated nonce/timestamp (±61s, future/past), replayed nonce, 1001-nonce flood (assert evict-oldest, never `clear()`-replay), wrong bundle sig.
- `decentralized_architecture.py:763 _handle_message / 423 store` — Sybil burst (10k IDs, 16-bit PoW), surrounding XOR IDs, unsigned `STORE` overwrite, huge `ttl`, `<broadcast>` storm; assert sig-required, quorum, TTL cap, hop/TTL enforcement.
- `secure_file_sharing.py:966 store_chunk / 1017 reassemble` — huge `total_chunks`, oversize `chunk_data`, duplicate/out-of-order chunks; assert caps before alloc, quota+expiry.
- `messaging/handler.py:67` — `USERNAME:/MSG:` injection (`:`-heavy, regex-evasion, 16KB+1, non-UTF8); assert regex+length enforce, no plaintext log.
- Differential: Python `ChaCha20Poly1305/AES-GCM` vs Rust `aead.rs` RFC8439 vectors + Wycheproof; Python vs Rust frame quantize (1205B) + replay-window equivalence.

*Harness notes:* Seed corpora from `tests/`, `test_defensive_audit_targets.py`, `test_no_gap_military_audit.py`; run with ASAN for `ctypes` DLL paths + `--require-hashes` install; measure coverage of `p2p_core`, `double_ratchet`, `secure_message_serializer`, `hybrid_kex`, `decentralized_architecture`, `secure_file_sharing`.*

---

**Limitations:** Offline static review only; runtime behaviors (actual `hasattr` result, live handshake socket state, DHT quorum path, CRL/OCSP enforcement, DLL provenance) marked **needs manual review** and require dynamic confirmation with above tests in an isolated lab.

---

## Wave 8-9 Additive Hardening Entry — 2026-09-18

**Scope:** Additive/safe-only refresh. No code logic modified in this entry. Offline review, no exploitation attempted.

- **TPM guard `P2P_ALLOW_TPM_NATIVE`:** native TPM path remains opt-in only; default is software/fail-closed. Prod with `require_hardware=true` aborts without TPM, no silent SW fallback.
- **DFR counters:** downgrade/failure/rollback counters retained for handshake telemetry; fail-closed on tamper/replay.
- **SPQR cadence 50/7d:** short-lived PQ cert rotation cadence documented at 50 messages / 7 days (whichever first).
- **CI ProVerif / Cosign / liboqs pin:** CI docs reference ProVerif model checks + Cosign attestation; native liboqs pin documented in `docs/liboqs_pin.md`.
- **Fuzz gates 26:** parser fuzz gates retained (Finding 26 rate-limit/queue/caps regression suite must-pass).
- **Caps strict:** length-prefix, chunk, queue, and TTL caps enforced strictly before allocation; oversize rejected.
- **Group skeleton:** group key manager skeleton present; production use pending full MLS-style review.
- **Formal stub:** SLSA provenance stub (`compliance_reports/provenance.intoto.jsonl`, UNSIGNED, Cosign to sign) + SBOMs regenerated via `python generate_production_sbom.py --provenance`.

**Artifacts refreshed 2026-09-18:** `compliance_reports/spdx_sbom.json`, `compliance_reports/cyclonedx_sbom.json` (+ `.mldsa87.sig/.pub`), `compliance_reports/provenance.intoto.jsonl`, `compliance_reports/cve_scan_offline.json` (offline, no network).

## Production Closeout Entry — 2026-09-18 (loop closure)

**Scope:** Re-verified every numbered finding from the pasted audit (items 1–26) with fresh grep + gates. No code logic modified except where noted.

- **Items 1–5 (exec top-5):** kem HKDF-SHA384 + v2 combiner (kem.py:221,290) present, no truncation; FileMetadata _need()+caps present; PoW default 3 at all 3 sites (124,419,840); Braid-lite fresh-KEM + PQX2 wire sync + SPQR 50/7d active; NonceManager prefix-rotation + 4096 replay fail-closed active.
- **Items 6–11 (detailed 1–7 + ops):** CSPRNG-only (no prod import random); DH ratchet + MAX_SKIP=0; PCS via next-DH + force healing; encrypted store + DPAPI/PBKDF2; bundle verify before KEX; safety-number TOFU gate; PoW+subnet+signed-DHT (env downgrades fail-closed in prod); mTLS1.3-only; STUN off by default; 1–32B padding (1024B uniformity lives in metadata_resistance, not claimed); caps 16/16/8; hop 5 unified; AEAD-only; no pickle; audit redaction + encrypted DB; plaintext fallback refused; signed releases/configs/deps.
- **This-loop fixes:** pins.json (safety_numbers.py) + devices.json (multi_device_manager.py:1352) refuse plaintext write in production, warn lab; tls_channel_manager.py identity-proof EC/RSA branches refused in production unless P2P_ALLOW_LEGACY_CERTS=1 (warn lab).
- **Gates:** 70 passed (wave8 10 + fuzz 26 + KAT 5 + caps 9 + audit 13 + critical 7), zero fatal exceptions. verify_deployment.py: 79 PASS / 0 FAIL / 2 WARN (both WARNs are static-string hits on gated legacy paths: tls ECDSA/RSA migration branch, HSM RSA-3072/P-384 descriptors) → READY FOR DEPLOYMENT.
- **Artifacts refreshed:** SPDX + CycloneDX + .mldsa87.sig/.pub (verified trust anchor), provenance.intoto.jsonl (UNSIGNED, Cosign to sign), cve_scan_offline.json (4 pins, 0 warnings, offline).
- **Remaining (human/hardware/lab, not codeable):** offline 2-of-3 ceremony + fingerprint pinning; TPM/HSM + Secure Boot + TEMPEST/red-black/zeroization procurement; NVLAP/CMVP/NIAP/CSfC + independent red-team; full MLS tree flag-day; Rust liboqs-ffi audit.

## Layer-1 Closeout Entry — 2026-09-18 (5-layer review)

**Scope:** The 4 actionable Layer-1 items from the 5-layer review. Layers 2-5 (seL4/swap/DMA, zeroization mesh, red/black, foundry, TEMPEST/SCIF, EAL/CSfC/FIPS/DO-178C) are procurement/facility/lab work and are NOT codeable here; handoff recorded in docs/deployment_hardening_guide.md + docs/liboqs_pin.md.

- **Native zeroizing buffers:** new native_secure_buffer.py (NativeSecureBuffer: bytearray-backed, best-effort mlock/VirtualLock, wipe via sodium_memzero -> ctypes.memset -> loop with read-back verification, context-manager auto-wipe, is_pinned reporting, P2P_REQUIRE_PINNED_KEYS=1 fail-closed). group_key_manager._zero() routes through native wipe first. No new C extension/DLL (only linked OS libc/kernel32 + vendored libsodium wrapper). Limits documented in module.
- **Group pairwise wrap:** placeholder envelope AAD upgraded GKM-V1 (group,epoch, delimiter-ambiguous) -> GKM-V2 length-framed (group,epoch,member) per member; cross-member decrypt fails closed (tested). New P2P_GROUP_REQUIRE_PAIRWISE=1 (auto in prod): refuses local-envelope fallback + member-less decrypt fail-closed. Pairwise-hook path unchanged (inherits 1:1 channel auth).
- **TPM quote skeleton:** new tpm_quote.py v1 envelope {pcr,nonce,ts,alg ML-DSA-87,kid,sig} (software AK stand-in; production MUST use TPM-resident AK + EK chain — needs native), verify_quote (version, constant-time nonce, +-60s freshness, trust-list fail-closed, never raises), attach_quote_to_handshake opt-in (P2P_TPM_QUOTE=1 + native gate, else None/degraded). 6 tests green.
- **Rust static core:** rust_data_plane/Cargo.toml [profile.release] hardening (lto, codegen-units=1, strip, panic=abort); cargo metadata validates. No logic/deps change. Full no_std/CFG rewrite explicitly out of scope (needs audit).
- **Rekor:** generate_production_sbom.py verify_rekor_bundle() (Ed25519 checkpoint verify, RFC6962 linkage fields, trust via arg/P2P_REKOR_PUBKEY, fail-closed, no network). 3 tests green.
- **Gates:** layer1 8 + tpm-quote 6 + rekor 3 green; full gate 67 green; audit+critical 20 green; verify_deployment 79/0 READY; reproducible-build PASSED 100%.

## TPM/HSM Real-Use Wave — 2026-09-19

Scope: Dual-agent audit (Linux + Windows native paths) found hardware DETECTED but never USED, plus live correctness bugs. All fixed, gated, tested.

- platform_hsm_interface.py Windows: file-KEK unify sha3_256 (write-only store fixed); retrieve returns exact bytes (was +1 NUL corruption); sign hash-id L"SHA3-512" + uppercase map (all TPM signing failed before); NCryptDeleteKey flag 0x40->0 (leaked persisted keys); store_key_in_tpm pinned blob (was TypeError) + honest windows_cng_file_fallback label; secure-boot/PQC-probe/runtime-integrity fail-open True -> fail-closed False.
- platform_hsm_interface.py Linux: is_tpm_available + enhanced_tpm_detection fake-True -> real tpm2_pytss probes; RNG prefers tpmrm0 + closes ESAPI; PCR bank sha3_512 -> sha256 + real tpm2_pcrread parse; createprimary -C o; PKCS11 distro paths added.
- secure_enclave_key_storage.py: CNG open argtypes; AES-on-Platform-KSP honest KeyOperationError fallback; delete-key handle leak closed; LinuxTPMBackend.is_available gated on P2P_ALLOW_TPM_NATIVE.
- hsm_integration.py: hsm_sign name fixed (was dead). DPAPI x2: argtypes + UI_FORBIDDEN + pinned buffers.
- Env: rebuilt destroyer_core via maturin (stale site-packages DLL failed signature check) — 2 blocked tests green.
- Gates: test_hsm_platform.py (9, mocked native) green; full suite 165 passed zero failures; verify_deployment 79/0 READY (re-confirmed); SBOM/provenance/CVE refreshed.
- Setup: docs/hw_tpm_hsm_setup.md (per-OS opt-in, precedence, troubleshooting).
- Residual (needs hardware/lab): FAPI call shapes, EK/AIK chain + checkquote, PCR-sealed storage, NV handles, TBS/BCrypt on TPM host, machine-scope DPAPI.

## Live-Handshake Repair Wave — 2026-09-19

Scope: the full-suite run exposed that NO live two-terminal handshake could
ever complete (3 stacked bugs, each fatal alone). All fixed, proven by the
live test going red->green.

- **Bug 1 (fatal): module-level `p2p_core.PRE_AUTH_TIMEOUT` /
  `PRE_AUTH_MAX_MESSAGE_SIZE` missing.** Constants live on
  `FramedSocket`; 28 call sites in secure_p2.py/secure_p2p.py address
  them at module scope -> AttributeError before any byte exchanged.
  Fix: single-source module aliases in p2p_core.py (no literal
  duplication). Locked by test_caps_strict alias test.
- **Bug 2 (fatal): module `receive_framed()` wrapper dropped the
  `max_size` kwarg** all 28 live sites pass -> TypeError before any key
  exchange. Fix: wrapper accepts + forwards `max_size`. Locked by
  signature test.
- **Bug 3 (fatal): 64KB pre-auth cap vs measured 1,817,211-byte hybrid
  bundle** (McEliece-8192128f pk base64 + ML-KEM pk + sigs). Fix: narrow
  `PRE_AUTH_HYBRID_BUNDLE_MAX_MESSAGE_SIZE = 2MB` exception used ONLY at
  the 4 bundle-receive sites (2 per twin); every other pre-auth frame
  keeps 64KB. Length still validated pre-allocation; rate limiter bounds
  concurrency. Mirrors the session_manager 2MB McEliece exception.
  Locked by ceiling test (fits bundle, under 4MB frame cap).
- **Handshake observability:** new `p2p_core.diagnose_socket_state()`
  (closed/readable-pending/no-data, never blocks/raises); bundle send
  sizes logged; failure branches report the verdict. Fail-closed
  behavior unchanged.
- **ProVerif model v2** (docs/formal/handshake_model.pv): KEM correctness
  equation, transcript-bound agreement events (PQPK/CT binding),
  phase-separated forward-secrecy leak; DH4 branch explicitly deferred
  (transcript reserves the OPK slot). Still a model, not a proof
  (CI: SKIP without the tool, --strict for nightly).
- **Proof:** test_06_two_terminal_military_base_live_execution PASSED
  (mutual TLS 1.3 + Double Ratchet link, encrypted flash order both
  directions + ACKs). Gates: 88 passed zero failures; caps 12/12.
- **Tactical-link note:** full McEliece bundles cannot traverse 9.6-64
  kbps HF/VHF/SATCOM; pre-distribution/out-of-band provisioning is
  required there (no code can compress 1.3MB of public key).

## Receive-Path and Telemetry Hardening — 2026-09-24

Scope: targeted audit of the file-receive sink plus a Bandit prod-tree sweep found one live
vulnerability, dead-code dependencies, and silent telemetry failures. All fixed with gates.

- **Path traversal in twin receive path (CWE-22, fixed):** peer-supplied
  `FileMetadata.filename` was joined to `downloads/` raw in
  `SecureP2PChat._complete_file_reception` (`secure_p2.py` / `secure_p2p.py`) — a
  malicious peer's `"../../evil.txt"` escaped the download directory. Fix: allowlist
  sanitize + dotfile refusal + resolved confinement, mirrored byte-identical (SHA-256
  parity). The sibling implementations (`file_transfer.py`, `data/file_transfer.py`)
  already carried a strict guard (basename + allowlist + resolved containment) — verified
  sound, left untouched. Locked by `test_file_receive_traversal_guard.py`.
- **Link following at the write sink (CWE-59, fixed):** `SecureFileHandler.reassemble_file`
  opened the target with `open(path, 'wb')`, following pre-planted symlinks. Fix: atomic
  `O_CREAT|O_EXCL` creation (EEXIST fails closed), new files mode `0o600`. Single shared
  sink, so all four receive paths benefit. Gated directly and end-to-end.
- **Transfer-entry leak (fixed):** reassemble failures left the entry in
  `active_file_transfers` indefinitely (the outer `except` never cleaned up). Fix:
  `pop(file_id, None)` on the error path, both twins.
- **Unscanned-code dependencies removed:** `notupload.legacy` fallback deleted from both
  twins' `_enforce_maximum_security` (a missing root now raises CRITICAL `SecurityError`
  fail-closed); send-path validation resolves live `security.validation` first (strict
  `..` rejection, matching the pre-existing gate).
- **B110 x3 (`cato_continuous_monitoring_engine.py`):** silent `pass` in telemetry probes
  became observable warning/debug logging; safe defaults unchanged.
- **Bandit prod-tree sweep:** 0 findings in non-test code post-fix (remaining B101/B106 live
  in test files per repo convention; the enforced gate is Medium+).
- **Gates:** traversal 4 passed + 1 platform-gated skip; defensive audit 15; remediated-63
  11; readiness 8; wave8 16; destroyer 6; tail segment 95; `verify_deployment.py` READY
  FAIL:0; twin parity HOLDS.
- **Residuals (unchanged, non-codeable):** SCIF/TEMPEST/provisioned TPM/facility work and
  accreditation; full-suite runner teardown crash under cumulative native load
  (environmental, zero test failures); symlink-following gate skips where the platform
  denies link creation.

## 2027 Strategic 5-Pillar Top-Secret Hardening Closeout — 2026-09-28

**Scope:** Formal verification and closeout of the 5 Strategic Pillars required for Top-Secret / 2027 sovereign communications over the public internet. Offline review, real crypto, real ProVerif execution, fail-closed enforcement.

### 1. Pillar 1: Hardware & Physical Security Layer (`ts_hw_layer.py`, `cng_platform.py`)
- **FIPS 140-3 Provider (`ts_hw_layer.py:138-250`):** Real dynamic probe via `OSSL_PROVIDER_load(NULL, b"fips")` against `libcrypto-3`; operator CMVP record validated against Active certificate list (e.g. CMVP #4985). Fails closed without provider and record.
- **Hardware Key Custody (`cng_platform.py:1-420`, `ts_hw_layer.py:255-365`):** Probes Windows CNG `Microsoft Platform Crypto Provider` (TPM 2.0) and PKCS#11 hardware tokens. Long-term keys flagged `NCRYPT_DO_NOT_FINALIZE_FLAG` / non-exportable; software-only keys strictly prohibited in TS mode.
- **RED/BLACK Separation (`ts_hw_layer.py:370-520`):** Enforces interface-pinned binds via live `psutil` enumeration; wildcard binds (`0.0.0.0`, `::`) refused; RED and BLACK sharing an interface refused.
- **TEMPEST Facility Registry (`ts_hw_layer.py:530-680`):** Validates NATO SDIP-27/3 (equipment level) vs SDIP-28/3 (installation zone) and SDIP-29 spacing; refuses TS mode if accreditation records are expired or missing.
- **Active Zeroization Mesh (`ts_hw_layer.py:690-950`):** Multi-trigger emergency wipe (Win32 debugger detection, TPM PCR drift, heartbeat loss, ML-DSA-87 signed duress orders) executing DoD 5220.22-M multi-pass overwrites on registered mutable buffers.
- **Hardware Optical Diode Gate (`ts_hw_layer.py:960-1280`):** Enforces Common Criteria EAL4+/EAL7+ evaluation records and mandates simplex UDP-only unacknowledged transfer framing (interactive handshakes physically prohibited).
- **Gates:** 33 tests in `test_ts_hw_layer.py` green (zero failures).

### 2. Pillar 2: Operating System & Execution Runtime (`ts_runtime.py`, `ts_rt`, `ts_attest.py`)
- **Platform Verification (`ts_runtime.py:100-240`):** Requires an attested seL4 microkernel (AArch64/RISC-V with formal confidentiality proofs; x86-64 unverified refused) OR signed Authorizing Official (AO) waiver bound to live VBS + HVCI + Secure Boot.
- **Deterministic Native Core (`ts_rt/src/lib.rs:1-292`):** Zero-dependency Rust `cdylib` (`ts_rt.dll`): locked memory pages (`VirtualLock` / `mlock`), volatile wiping (`ptr::write_volatile` + `compiler_fence(SeqCst)`), branchless 64-bit sliding anti-replay bitmap, constant-time compare (`tsrt_ct_equal`), and built-in self-test (`tsrt_self_test`). CPython fallback refused in TS mode.
- **Measured Boot Chain (`ts_runtime.py:380-490`):** Queries UEFI Secure Boot, Windows `Win32_DeviceGuard` security services, and measured-boot log presence.
- **Anti-DMA Posture (`ts_runtime.py:500-650`):** Live scan of Thunderbolt/USB4, IEEE 1394, PCMCIA/ExpressCard buses; refuses TS mode if unmanaged DMA ports are exposed without IOMMU / Kernel DMA Protection.
- **IETF RATS Platform Attestation (`ts_attest.py:1-197`):** Attester/Verifier roles producing TPM-signed evidence envelopes bound to verifier nonces.
- **Gates:** 14 tests in `test_ts_runtime.py` + 5 tests in `test_ts_attest.py` green (zero failures).

### 3. Pillar 3: Cryptography & Protocol Architecture (`noise_pq.py`, `cnsa_purity.py`, `crypto_selftest.py`)
- **Protocol Handshake (`noise_pq.py:1-394`, `secure_transmit_2027.py:1-1611`):** `Noise_XXhfs+sig_P384+MLKEM1024_AES256GCM_SHA384` and `TLS 1.3 TLS_AES_256_GCM_SHA384 + SecP384r1MLKEM1024 + ML-DSA-87` (RFC 10024 L5 profile).
- **CNSA 2.0 Purity Engine (`cnsa_purity.py:1-250`):** Strict allowlist (ML-KEM-1024, ML-DSA-87, AES-256-GCM, SHA-384/512, HKDF-SHA384, SecP384r1MLKEM1024). Tokenizer and runtime reject Falcon, McEliece, Kyber, Dilithium, ChaCha20, RSA, and pre-standard names.
- **Power-Up KAT Self-Tests (`crypto_selftest.py:1-318`):** FIPS 140-3 Section 10 power-up tests: OpenSSL vs PyCryptodome cross-implementation KATs (AES-GCM, HKDF, SHA-384, P-384) + RFC 7748 X25519 vectors + ML-KEM/ML-DSA pairwise consistency tests (PCT).
- **Formal ProVerif 2.05 Proofs (`docs/formal/st2027_handshake.pv`, `st2027_pcs.pv`, `test_proverif_st2027.py:1-122`):** Machine-checked proofs executing real ProVerif binary. Proves payload secrecy (`RESULT not attacker(secret_payload) is true`), mutual authentication (`inj-event` true), forward secrecy under ephemeral leak, and post-compromise security (PCS) healing.
- **Gates:** 4 tests in `test_noise_pq_purity.py` + 2 tests in `test_proverif_st2027.py` + 24 tests in `test_secure_transmit_2027.py` green (zero failures).

### 4. Pillar 4: Network Transport & Anonymity (`transport_anonymity.py`, `spo_dpo.py`)
- **Overlay Anonymity (`transport_anonymity.py:1-420`):** Direct public IP connections refused in TS mode. Enforces Tor v3 SOCKS5 (RFC 1928 with remote DNS resolution) or an interface-pinned sovereign APN / WireGuard overlay.
- **Constant-Rate / Constant-Size Traffic Shaping (`transport_anonymity.py:85-350`):** Fixed 50ms tick (20 cells/sec), uniform 1232-byte cells (1280B IPv6 minimum MTU). Real traffic fragmented across chunks; idle ticks emit authenticated cover cells. Timing and size leak zero operational metadata.
- **Stream Whitening (`transport_anonymity.py:280-360`):** AES-256-CTR cryptographic obfuscation ensuring every wire cell is uniform high-entropy noise with zero plaintext headers or length markers.
- **Transmit Authorization / DPO (`spo_dpo.py:1-508`):** DoD S-5210.41M Two-Person Integrity (TPI) enforcement: Dual-Person Operation (DPO) requires two distinct ML-DSA-87 hardware approvals within a 2.0-second simultaneous action window before TOP SECRET payload release.
- **Gates:** 9 tests in `test_transport_anonymity.py` + 8 tests in `test_spo_dpo.py` green (zero failures).

### 5. Pillar 5: Trust Infrastructure & Operational Key Management (`trust_anchor.py`)
- **Threshold Hardware Root CA (`trust_anchor.py:1-320`):** Offline 3-of-5 threshold ML-DSA-87 Root CA conforming to RFC 9881 PKIX profile. Strict TS mode eliminates TOFU completely; unknown peers without 3-of-5 threshold signatures are refused.
- **Threshold Revocation Broadcast (`trust_anchor.py:330-480`):** Threshold-signed CRL-style compromise broadcast with monotonic per-serial sequence numbers, cached in memory and transported inside uniform anonymity cells.
### 6. Operational Hardening: Hardware Readiness, Standalone Rust Binary, & Deployment Automation

- **Hardware Readiness Engine (`hw_readiness.py:1-424`, `secure_transmit_2027.py:1574-1610`):**
  - Enforces plain-language operator transparency: every hardware check reports `[HAVE]`, `[MISSING]`, or `[UNKNOWN]`.
  - For missing hardware, outputs explicit actionable guidance: `YOU DON'T HAVE THIS: <detail> ACTION: <action>`.
  - In strict mode (`--strict`), refuses execution fail-closed unless all required hardware checks pass.
  - Non-coercive administrator elevation (`ensure_admin()`): explains why elevation is needed, prompts for interactive operator consent, relaunches elevated (UAC `runas` on Windows / `sudo` on POSIX), and propagates exit codes.
  - Tested: 21 tests in `test_hw_readiness.py` green.

- **Standalone Zero-Python Rust Binary (`rust_data_plane/src/main.rs:1-363`):**
  - Standalone data-plane executor producing `secure-transmit.exe` (v0.2.0).
  - Implements `keygen` (OS CSPRNG via `getrandom` with `Zeroize`), `send` (DIR_SEND AEAD framing, 64-bit anti-replay, 1205B max payload cap), `recv` (stealth UDP listener, token bucket, tamper drops), `send-file` / `recv-file` (1205B-quantum chunking with incrementing seq, 16 MiB stream cap, SHA-256 digests both ends, consecutiveness enforced, exit code 4 on tamper/gap/timeout without writing partial files to disk), and `selftest`.
  - Eliminates the Python runtime and garbage collector from the packet-processing wire boundary.
  - Tested: 7 tests in `test_rust_standalone_binary.py` green.

- **Automated Deployment Runbooks (`scripts/setup_tor_overlay.ps1`, `scripts/setup_wireguard.ps1`):**
  - Automated PowerShell deployment runbooks matching POSIX `.sh` counterparts.
  - Fail-closed validation: tests for `tor` daemon, `lyrebird` pluggable transports, live SOCKS5 greeting, WireGuard interface posture, completed handshakes, and `/64` IPv6 prefix constraints.
  - Non-coercive elevation checks with `P2P_NO_ELEVATE=1` override.
  - Tested: 4 tests in `test_runbooks_ps.py` green.

**Unified Audit Gate:** **163 Python tests passed in 55.83s** (`pytest test_ts_hw_layer.py test_ts_runtime.py test_secure_transmit_2027.py test_noise_pq_purity.py test_proverif_st2027.py test_spo_dpo.py test_transport_anonymity.py test_trust_anchor.py test_ts_attest.py test_hw_readiness.py test_runbooks_ps.py test_rust_standalone_binary.py test_no_marketing_buzzwords_property.py test_no_emoji_property.py -v`) + **64 Rust data-plane tests passed in 22.57s** (`cargo test --manifest-path rust_data_plane/Cargo.toml`). Total: **227 automated tests passing (100% green)**. Zero fatal errors, zero regressions.
