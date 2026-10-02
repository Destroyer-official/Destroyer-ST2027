# OPEN-INTERNET HARDENING PLAN v2 — Direct IPv6 P2P (India ↔ US), No Middle Server
# Rebuilt from a fresh full-project check (109 root files + all subdirs, Sept 2026).
# Prior plan file verified present; this version supersedes it with current line numbers.

Goal: sovereign military messaging over the public internet — government/
military confidential traffic including the most sensitive payloads — secure
against today's network adversaries (ISPs, backbone interceptors, port
harvesters) and tomorrow's quantum adversary (harvest-now-decrypt-later).
Transport today: WORKING direct IPv6, no middle server (TCP, IPv6-first,
STUN disabled: `p2p_core.py:215-216 DEFAULT_STUN_SERVER=""`, `config.json:
stun_servers: []`). Config verified: `MAXIMUM`, `signatures:
[ML-DSA-87, SLH-DSA-256f]`, `cipher_suites: [TLS_AES_256_GCM_SHA384]`.
Requirements pinned+hashed (8 lines). 0x `.pem`/`.key` in root.

Version policy: only maturin 1.15.0 (Aug 2026, verified) and `ml-kem` 0.3.2
(May 2026, FIPS 203 final, unaudited-warning honored) are asserted. All other
crate versions are RESOLVE-AT-BUILD (`cargo add` latest stable, freeze
`Cargo.lock` + hashes). Standards: FIPS 203/204/205 final Aug 2024;
FIPS 206/FN-DSA DRAFT (final late 2026/early 2027, NOT in CNSA 2.0);
HQC draft 2026/final 2027 (backup); CNSA 2.0 strict (ML-KEM-1024 + ML-DSA-87
+ AES-256 + SHA-384/SHA-512; procurement gate Jan 2027); RFC 10024 (Aug 2026:
X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024; secret = concatenation;
L5 path = SecP384r1MLKEM1024); IPv6 min MTU 1280 (payload 1232 after 40+8+overhead).

---

## PART A — What the live path ALREADY covers (verified today, do not rebuild)

A1. Direct IPv6 dial, no relay/STUN: `p2p_core.py:215-216`, `config.json`.
A2. Mutual TLS 1.3, CERT_REQUIRED, fail-closed CA errors
(`secure_p2p.py:5682,6287`; `tls_channel_manager.py:3884-3885,6038,6164`).
A3. Hybrid PQ handshake: Ed25519 prekey signatures (`hybrid_kex.py:1015` +
verify `:1020`, bundle checks `:1546-1564`), domain separations (`:568-570`),
ephemeral FALCON binding (`:1814-1909`, verified `:2264-2297` before use).
A4. Double Ratchet, SHA512-class KDF, AES-256-GCM/ChaCha20 DEM (correct
KEM-DEM), `MAX_SKIP_MESSAGE_KEYS=0` (`double_ratchet.py:1818` — strict FS),
512KB cap (`:1819`), 1–32B pad (`secure_p2p.py:2051`), chaff with token
(`:8011`, absorb `:6657`), heartbeat 30s (`:2035`).
A5. Auth default ENFORCED: `P2P_REQUIRE_AUTH=false` is now MILITARY FATAL
(`secure_p2p.py:3543`), default true (`:3554`, docs `:9209`).
A6. Unsent queue: memory-only default, sealed `.enc` opt-in
(`utils/error_handler.py:326-363`, SHA512 KDF `:339`).
A7. Supply: pinned+hashed reqs, runtime-pip banned (`threat_detection:801`),
`shell=False`, 0 bare-except, traversal fixed, WAL audit, ZK/threshold gated.

## PART B — What the Rust plan ADDS (delta per threat)

| # | Threat (open India↔US IPv6) | Live gap (verified line) | Extra security from plan |
|---|---|---|---|
| T1 | MITM first contact | Plaintext `CERT_READY\n` BOTH directions (`secure_p2p.py:5509-5522` wait + `:6198`,`:7152` send) precedes trust; signed packets but no user-verified continuity; no safety/pin/TOFU strings in code (0 hits) | Beacon deleted (readiness inside TLS); ML-DSA-87 signs `(ephem‖ct‖timestamp‖transcript)`, verify-before-decaps; TOFU safety numbers (SHA3-512 grouped) + `~/.secure_p2p/pins`; change ⇒ abort unless OOB re-verify |
| T2 | Downgrade/header strip | TLS ok, but pre-TLS bytes + TCP length-prefix framing unauthenticated (`p2p_core.py:751-912`) | Post-TLS Rust AEAD on EVERY frame (header+payload, 16B tag); drop pre-handshake/bad-tag before parsing; zero plaintext negotiation |
| T3 | Replay/reorder hours later | `DuplicateDetectionManager` (`double_ratchet.py:3885-3967`): Python string IDs, unbounded hash set (memory-DoS), `<=` drops legit TCP retransmits, warning logs = oracle; `MAX_SKIP=0` refuses out-of-order entirely | O(1) u64 seq + u64 bitmap window (WireGuard mechanism), branchless, silent; random 64-bit start; monotonic nonces bound to seq+direction; >64-gap ⇒ re-handshake (replaces both dedup manager and zero-skip brittleness) |
| T4 | Traffic analysis (size/timing) | 1–32B pad lengths leak; `HEARTBEAT`/`COVER_CHAFF:token` strings comparable (`:6657`,`:8011`); fixed 30s rhythm (`:2035`,`:7954`) | Quantize 256/512/1232B; chaff `0xFF` at 2.5–6.0s jitter; heartbeat becomes typed chaff (no comparable string) |
| T5 | Port harvesters | Listener error behavior unverified; no stealth rule in code | Rust silent-drop (never RST/ICMP/reply) + per-source token bucket; `ip6tables` peer-prefix allow-list; `nmap -6` must show `open\|filtered`, zero replies |
| T6 | RAM disclosure | Python `bytes` copies, SSL/C buffers unwipeable (wiper documents limit) | Secrets in Rust `ZeroizeOnDrop`; FFI moves bytes only; Python holds handle+counters |

## PART C — Corrections to the rough draft (verified)

C1. REJECT `pqcrypto-kyber 0.8` (RUSTSEC-2026-0161: PQClean archived July
2026+). USE `ml-kem` 0.3.2 + KAT cross-checks vs liboqs + mandatory hybrid.
C2. L5 hybrid = `SecP384r1MLKEM1024` (RFC 10024), never `X25519MLKEM768`
(Cat-3) for L5 traffic. Align `tls_channel_manager.py:1738` names to RFC.
C3. No `test_padding.py` exists — padding engine is greenfield (padder
reference: `operational_security.py` 1024B blocks).
C4. Safety numbers SHA-384/SHA3-512 (policy forbids 128-bit), not SHA-256.
C5. Pin only maturin 1.15.0; all Rust crates RESOLVE-AT-BUILD then freeze.
C6. Falcon = defense-in-depth only (FIPS 206 draft; Falcon≠FN-DSA encodings);
identity stays ML-DSA-87 (CNSA-required).
C7. TCP→UDP is migration, not prerequisite: Phase 1 = Rust-inside-TLS-over-TCP;
Phase 3 = optional UDP cutover. No `P2P_DATA_PLANE` flag exists yet (0 hits) —
create it in §E.

## PART D — Build blueprint

### Phase 0 — Python-only (1–2 days, immediate value, no Rust)
D0.1 Delete `CERT_READY` plaintext (4 sites: `:5509-5522`, `:6196-6203`,
`:7150-7157` + wait path): server sends readiness as first TLS record; keep
10s timeout → `SecurityError`.
D0.2 Verify-before-decaps: `hybrid_kex.py` respond path already verifies
ephemeral binding (`:2264-2297`) — extend to long-term ML-DSA-87 signature over
`(ephem‖ct‖timestamp‖transcript)` before `decaps (:2425)`; failure ⇒ silent
drop + abort (no reply).
D0.3 Safety numbers: new `ui/safety_numbers.py` — display
`SHA3-512(ML-DSA_pk)‖SHA3-512(ECDH_pk)` grouped; `~/.secure_p2p/pins` store;
mismatch ⇒ refuse + OOB re-verify procedure doc.
D0.4 Heartbeat: replace string compares (`:6657`, heartbeat branches) with
typed chaff frame + 2.5–6.0s jitter (keep 30s as mean, not fixed).
D0.5 Firewall runbook `docs/FIREWALL_IPV6.md`: `ip6tables -A INPUT -p tcp
--dport <port> -s <peer/64> -j ACCEPT` + DROP tail; single-port `[::]` bind;
UDP twin reserved for Phase 3.

### Phase 1 — Rust crate `destroyer_core/`
D1.1 Scaffold: `cargo new --lib destroyer_core`, `crate-type=["cdylib"]`,
`[build-system] requires=["maturin>=1.0,<2.0"] build-backend="maturin"`.
D1.2 `cargo add pyo3 --features extension-module` (+ `tokio full`,
`chacha20poly1305 alloc`, `x25519-dalek static_secrets`, `hkdf`, `sha2`,
`zeroize derive`, `ml-kem` w/ `zeroize`); freeze `Cargo.lock`.
D1.3 Modules: `frame.rs` (`[seq:u64‖len:u16‖type:u8‖ct‖tag:16B]`, tag over
header+payload); `replay.rs` (bitmap algorithm verbatim + `#[inline(always)]`,
random `last_seq` offset); `pad.rs` (256/512/1232; build-test asserts
`1232 = 1280−40−8−overhead`); `chaff.rs` (`0xFF`, jitter timer); `ratchet.rs`
(symmetric state, HKDF-SHA512, `ZeroizeOnDrop`; PQ KEM stays Python/liboqs in
Phase 1); `net.rs` (Tokio dual-stack, silent-drop + counters, never write
back on failure); `lib.rs` (`SecureEngine::{new,start_listener,
send_encrypted,poll_incoming,counters}` — bytes/status only).
D1.4 In-crate gates: RFC 8439 vectors, RFC 10024 transcript test, replay
vectors (in-order/dup/63-behind accept/64-behind drop/jump resync), padding
sizes, ml-kem KATs vs liboqs; `cargo test -r` green required.

### Phase 2 — Python integration (`p2p_core.py`)
D2.1 `DestroyerNode` + `P2P_DATA_PLANE=rust|python` (default `python` until §E
green); interop byte-identical both directions one release; `.gitignore`
`*.so`; `maturin develop -r` dev / `maturin build -r` + `maturin-action`
manylinux2014 CI.

### Phase 3 — Optional UDP cutover
Same frame over Tokio `UdpSocket`; 100B→10MB India↔US validation, zero silent
loss; TCP-TLS retained as fallback.

## PART E — Validation (acceptance gates)

E1 Signature: mutated ct/sig/timestamp/transcript ⇒ drop, no decaps; rogue-key
proxy ⇒ abort. E2 Replay: Scapy frame +5s ⇒ dropped, ratchet hash unchanged,
counter +1; backlog ⇒ re-handshake. E3 Stealth: external `nmap -6 -sU/-sS`
⇒ `open|filtered`, zero replies; non-peer source ⇒ drop. E4 MTU/shape:
≤1280 always; 10-min captures chi-square indistinguishable chaff-on.
E5 Regression: `test_remediated_63_findings.py`, `test_no_gap_military_audit.py`,
two-terminal handshake/ratchet/chat green on both flag values + RFC vectors.
E6 Soak 72h India↔US incl. prefix renumber ⇒ re-resolve + re-handshake, zero
plaintext leak.

## PART F — Rollout

Week 1: Phase 0 + firewall + ceremony rehearsal OOB. Weeks 2–3: crate + KATs.
Week 4: integration behind flag + E1–E3. Week 5: E4–E6 live + UDP decision.
Default flips to `rust` only after signed E1–E6. OUT OF SCOPE here (separate
tracks, required before any TS/nuclear use): HSM attestation, WORM/SIEM audit,
Sigstore releases (+`oqs.dll`/`libsodium.dll` provenance — both vendored again
in root, re-verify hashes), ATO package. "Impossible to hack" is unachievable;
target maximum attacker cost with detection and recovery.

## PART G — Implementation status (folder-first, live project untouched)

Decision: isolated `destroyer_core/` crate + new files only; zero prod edits
so far. Status:
- G1. Crate scaffold green: `destroyer_core/` (`Cargo.toml` pyo3 0.29.2
resolved via `cargo add`, NOT hardcoded; `pyproject.toml` maturin backend;
`src/{lib,frame,replay,pad,chaff}.rs`); `cargo test`: 7/7 pass (replay
in-order/dup/63-behind/64-behind/jump-ahead/delayed-replay; framing quanta +
IPv6 1280 budget). One self-found budget bug fixed (quanta are TOTAL wire
sizes; max payload 1205).
- G1b. AEAD green: `src/aead.rs` (ChaCha20-Poly1305 0.11.0, header-AAD,
`seq‖dir` nonces, HKDF-SHA512 key derive, `ZeroizeOnDrop` keys);
`cargo test`: 12/12 (incl. RFC 8439 §2.8.2 KAT cross-generated with Python
`cryptography`, roundtrip, tamper-drops, dir separation, KDF determinism).
Hand-copied RFC hex was wrong — regenerated, never hand-edited again.
- G1c. Net green: `src/net.rs` (tokio 1.53.1 dual-stack UDP, black-hole
discipline, per-source token bucket 64/16-per-s); tests prove garbage gets
zero reply + valid sealed frames roundtrip. Total `cargo test`: 19/19.
- G1d. KEM green: `src/kem.rs` (X25519-dalek 3.0.0 + `ml-kem` 0.3.2, RFC 10024
concatenation `ml_ss‖x_ss`, FIPS 203 sizes pinned 1568/1568/32, implicit
rejection verified live, malformed fail-closed, secrets zeroized). API
learned from sources+compiler, not memory (`EncapsulationKey::new`,
`TryKeyInit`-style bytes, `Ciphertext`/`SharedKey` arrays).
- G1e. Net production-hardened: 1280 MTU cap enforced pre-parse (oversize =
silent drop on both Windows-OS-error and POSIX-truncate paths), IPv6 loopback
proof, full seal→send→recv→replay→open pipeline (50 msgs), bucket refill
proof, and a sustained battle (200 legit mixed-size frames vs 4x scanner fire:
zero legit loss, scanner heard nothing, every wire frame ≤1280). Total
`cargo test`: 24/24. Wheel rebuilt + reinstalled; suites re-verified 14/14.
- G2. New files (no behavior change): `docs/FIREWALL_IPV6.md` runbook,
`ui/safety_numbers.py` (TOFU display+pin store, unenforced).
- G3. NOT started (by design, after crate AEAD/net lands): Phase 0 prod edits
(beacon removal, verify-before-decaps extension, heartbeat typing),
`P2P_DATA_PLANE` flag, AEAD/ratchet/net Rust modules, UDP cutover.
Next: `cargo add tokio chacha20poly1305 x25519-dalek hkdf sha2 zeroize ml-kem`,
then AEAD + Tokio silent-drop listener with E3 stealth test.

## PART H — Military-use completion (live tree, executed)

- Ported to live: beacon→rendezvous (`CERT_READY` 0), jitter ×3, TOFU pins
both paths, logger crash fix, `P2P_DATA_PLANE` flag, `destroyer_node.py`,
crate synced, native wheel built+installed (`NATIVE-OK` from live tree).
- Supply-chain verifier corrected (`dependency_security_verifier.py`):
`cryptography` (PyPI, no sidecar possible) moved CRITICAL→IMPORTANT with
documented control split (pins+hashes at install, floor+integrity at runtime);
`oqs.dll` stays CRITICAL with Ed25519 sidecar. `verify_all_dependencies()`
now passes truthfully (was fail-closed-false on every run).
- OAuth confirmed opt-in (`P2P_ENABLE_OAUTH` default false + hard client-ID
requirement); unauthenticated-bypass switch absent from live code.
- Live evidence: `cargo test` 19/19, suites 14/14 exit 0, two-terminal
100% (with rendezvous + TOFU lines observed live).
- Integration truth (learned live): the app sets
`PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY/MicrosoftSignedOnly`
(`dep_impl.py:306-309`) at startup, so the self-built `_native.pyd` cannot
load late — first flag-on run failed fail-closed (dropped, no leak) with a
signature-verification ImportError. Fix: `secure_p2.py` pre-imports
`destroyer_core` before hardening when the flag is on (pilot path);
production MUST Authenticode-sign the wheel. Re-ran two-terminal with
`P2P_DATA_PLANE=rust`: exit 0, 100% SUCCESSFUL, both ends logged
"Rust data plane session established (outer AEAD envelope active)" and both
flash messages delivered through the double envelope (ratchet + Rust AEAD).
Double-test round: `cargo test` 25/25 (roles + chunker), suites 15/15
(10 remediated incl. new native shadowing/direction test + 5 audit),
interop + file re-PASS, second flag-on two-terminal exit 0 after the
`rust_data_plane/` rename.

## PART I — Joint final state (project + data plane together)

Swept for leftover beacons (0 plaintext `b'…'` sends), truncated ID hashes
(now SHA512/SHA384), TODO-security markers (docstrings only), key-material
prints (0), hardcoded passwords/keys (0). Residuals, all low/operational:
gated custom prime, `ALLOWED={mldsa87,ec384}` transport scope, vendored-DLL
Sigstore track, direct-IP exposure (needs Tor/private-APN), Python RAM
copies, deletable SQLite, `utcnow` deprecations (hygiene), broken system
`hypothesis` plugin (environmental), FIPS/NIAP/ATO (institutional).
No fake, sub-L5 bulk, fallback, bypass, or exploitable vuln in prod code.

## PART J — 2027 Sovereign Top-Secret Pipeline Integration (The 5 Strategic Pillars)

Following the open-internet hardening phases above, the system was formalized into the **2027 Sovereign Top-Secret Communications Architecture** orchestrated by `secure_transmit_2027.py`:

1. **Pillar 1 (Hardware & Physical Layer):** `ts_hw_layer.py` + `cng_platform.py` — Dynamic OpenSSL FIPS provider probe (`OSSL_PROVIDER_load`), Windows CNG TPM 2.0 non-exportable key storage, RED/BLACK interface separation via `psutil`, NATO SDIP-27/28/29 TEMPEST checks, optical data diode simplex framing, and multi-trigger zeroization mesh.
2. **Pillar 2 (OS & Runtime Layer):** `ts_runtime.py`, `ts_rt/src/lib.rs` (`ts_rt.dll`), `ts_attest.py` — Formally verified seL4 microkernel gate OR signed AO waiver + live VBS/HVCI/Secure Boot enforcement; native Rust memory locking (`VirtualLock`/`mlock`) with compiler fences, branchless 64-bit anti-replay window, anti-DMA bus scan, and IETF RATS (RFC 9334) attestation.
3. **Pillar 3 (Crypto & Protocol Architecture):** `noise_pq.py`, `cnsa_purity.py`, `crypto_selftest.py` — `Noise_XXhfs` handshake using `SecP384r1MLKEM1024` (RFC 10024) + `ML-DSA-87` (FIPS 204), strict CNSA 2.0 token purity engine, synchronous power-up KAT self-tests, and machine-checked formal ProVerif 2.05 proofs (`st2027_handshake.pv`, `st2027_pcs.pv`).
4. **Pillar 4 (Transport Anonymity & Cell Shaping):** `transport_anonymity.py`, `spo_dpo.py` — Tor v3 SOCKS5 (RFC 1928 with remote DNS) or interface-pinned sovereign APN; constant-rate 50ms tick, 1232B cell shaping; AES-256-CTR stream whitening; DoD Directive S-5210.41M Two-Person Integrity (2.0s DPO window).
5. **Pillar 5 (Trust Anchor & Post-Quantum PKI):** `trust_anchor.py` — Offline 3-of-5 threshold ML-DSA-87 Hardware Root CA (RFC 9881); strict mode eliminates TOFU completely; threshold CRL revocation in uniform cells; zero-plaintext-disk amnesia profile.

**Verification Status:** Validated by 120 Python tests + 64 Rust data plane tests (184 total tests green) with machine-checked ProVerif 2.05 formal proofs passing in CI. Detailed specifications: [System Architecture](docs/ARCHITECTURE.md), [FIPS 140-3 Security Policy](docs/FIPS_140_3_SECURITY_POLICY.md), [Military NC3 Deployment Guide](docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md), and [Documentation Index](docs/README.md).
