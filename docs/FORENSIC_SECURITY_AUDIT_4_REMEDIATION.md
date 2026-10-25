# Destroyer-ST2027: Fourth Forensic Security Audit Remediation

**Target Baseline:** `Destroyer-ST2027` (audit cycle 2026-10-17), repository root `D:\code\Main_projects\p2p\p2p_6_1-26`
**Audit Scope:** Fourth independent forensic review of the Python control plane and tactical modules: signature verification paths, replay and rate limiting, file-transfer and archive ingestion, discovery broadcasts, key-store at-rest derivation, audit chain integrity, audit receipt signing, and web console input handling.
**Classification Posture:** Consistent with repository security documentation conventions.
**Verification Date:** 2026-10-17
**Status:** All confirmed findings remediated, regression-tested, and verified; master defense audit 10/10 gates green on consecutive runs.

---

## 1. Executive Summary

This document records the remediation of the fourth audit cycle register (A4-01 through A4-26, plus two sub-findings discovered during verification). Each finding was lead-verified against source before remediation; each fix is accompanied by source or behavioral regression coverage in `tests/test_audit4_remediations_2026_10_17.py` (26 tests) and the existing suites (210 passed, 4 platform-gated skips across the combined regression battery).

Two additional defects (A4-15b, A4-17b) were discovered by the new regression tests and by re-running the audit pipeline: Windows `os.open`/`os.write` default text mode expands `0x0A` bytes of random binary key material to CRLF, corrupting persisted secrets while `os.write` still reports a full write. Both were repaired, including a deterministic, verify-after-sign-checked recovery path for already-corrupted artifacts.

The TLS hostname-verification observation (F4) from the register was resolved by design review rather than a code change: the default cover-SNI domain-fronting posture intentionally keeps PKI hostname checking off while peer identity is pinned in the inner Noise/PQ handshake. It is documented as a residual risk and the client context now emits a one-time operator warning.

---

## 2. Methodology and Verification Changes

* Findings were verified by direct source inspection before any edit; severity reflects exploitability at the time of confirmation.
* Every remediation was compile-checked (`py_compile`) and exercised by tests. Behavioral tests use real post-quantum primitives (ML-DSA-87, FALCON-1024) where the defect involves verification outcomes.
* Regression tests are deliberately adversarial: forged signatures, replayed packets, duplicate custodians, oversized frames, truncated STUN attributes, CRLF-inflated key files.
* Identifier note: register IDs are retained for traceability; not every reserved identifier maps to a confirmed defect (A4-21 did not survive lead verification as a reproducible issue).
* The master audit pipeline (`scripts/run_defense_audit.py`) was executed on consecutive runs to prove the A4-17 persistence round-trip; the final receipt signature was independently verified against the published public key outside the audit script.

---

## 3. Finding and Remediation Register

| Finding ID | Severity | Area | Root Cause | Production Remediation | Verification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A4-01** | **Critical** | `hybrid_kex.py` handshake | Handshake path computed `self.dss.verify(...)` but discarded the return value, then proceeded as if the FALCON signature had verified (full signature bypass on that path). | `sig_ok = self.dss.verify(...)` is checked; `if not sig_ok: raise ValueError(...)` with explicit failure. | Source guard test + FALCON-1024 forged-signature behavioral test (good `True`, bit-flipped `False`, wrong-message `False`). |
| **A4-02** | High | `secure_key_manager.py` `hybrid_verify` | FALCON branch returned `True` unconditionally; `verify()` result was discarded, silently accepting forged signatures. | `results[algo_name] = bool(algo_instance.verify(public_key, message, signature))`. | Behavioral test using the real FALCON-1024 engine via `object.__new__` (full class ctor pulls the HQC agility reserve). |
| **A4-03** | Medium | `remote_siem_forwarder.py` | Audit chain link comparison used Python `!=` on hex strings (short-circuit timing leak on attacker-guessable chain links). | Module `_ct_eq_str()` via `hmac.compare_digest`, type-guarded; applied to both `prev_hmac` and recomputed HMAC comparisons in `verify_audit_log_chain`. | Unit test (equal/unequal/None/int) + persisted-ledger tamper detection test through the constant-time path. |
| **A4-04** | High | `tactical_operator_console.py` (PTT) | `PTT_VOICE` bursts were accepted and displayed without authentication; a "Decrypted" label overstated what was verified; spoofed bursts could be injected. | `canonical_ptt_bytes()` canonical form; `send_ptt_burst` signs with the station key and attaches `sig`; `_process_ptt_packet` verifies against the enrolled signer, rejects unknown signers, bad signatures, and stale/future timestamps (±120 s); label changed to reflect authenticated metadata only. | Signed-accepted / tampered-rejected / unsigned-rejected behavioral tests with real ML-DSA-87 keys. |
| **A4-05** | Medium | `tactical_operator_console.py` (EAM) | EAM execution had no nonce replay suppression: a captured emergency action message could be re-executed. | Per-station `_eam_seen_nonces` cache (600 s TTL) checked after signature/freshness validation; missing or short nonces rejected. | Replay test: first delivery executes, identical packet second delivery is refused. |
| **A4-06** | Medium | `decentralized_architecture.py` (WiFi Direct) | Frame length taken from the wire without bounds; a forged 4 GiB length could trigger unbounded allocation (DoS). | `MAX_FRAME_BYTES` 16 MiB cap plus zero-length rejection in `receive_data`; the connection is dropped on violation. | Fake-socket tests: `0xFFFFFFFF` and zero lengths return `None` and disconnect. |
| **A4-07** | High | `secure_file_sharing.py` | File-completion path joined an unvalidated peer-supplied filename onto the output directory (traversal write outside the destination). | Module `_sanitize_transfer_filename()` (basename, path separators, control chars, dot-leading names rewritten) and a resolve-containment check under `output_dir` before writing. | Sanitizer cases plus `_complete_file_transfer` containment test with real `FileMetadata`/`FileChunk` dataclasses. |
| **A4-08** | High | `air_gapped_operation.py` (discovery) | Unsigned discovery broadcasts were accepted, and broadcasts with a provided-but-invalid signature were silently downgraded to unsigned acceptance. | `_require_signed_discovery()` policy: production or `P2P_REQUIRE_SIGNED_DISCOVERY=1` requires signatures; provided signatures must verify (fail closed); unsigned lab mode logs a warning; explicit `P2P_ALLOW_UNSIGNED_DISCOVERY=1` opt-out never overrides production. | Tests: unsigned accepted in lab default, rejected under strict policy, invalid-signature packet rejected in lab mode. |
| **A4-09** | High | `tactical_web_console.py` | Demo EAM endpoint accepted bare signature strings and reported "VERIFIED"; no body-size cap, no origin check; replay possible; zeroize and CoT endpoints overclaimed. | Real ML-DSA-87 dual-custody verification over `canonical_web_eam_bytes()`; replay cache (3600 s TTL, 409); duplicate-custodian rejection; missing/incomplete custody packages never reported as verified; 1 MiB POST body cap (413); `ALLOWED_ORIGINS` guard (403); zeroize requires `{"confirm": "ZEROIZE-ALL"}`; CoT signature label corrected to `NOT_SIGNED_LOCAL_DEMO`. | 8 handler-level tests: real dual-sign roundtrip, replay 409, forged 403, duplicate custodian, origin guard, body cap, zeroize confirmation. |
| **A4-10** | Medium | `destroyer.py` (diode PSK) | Hardcoded, world-known PSK written to a shared temp path for diode provisioning. | `_provision_diode_key_material()`: `P2P_DIODE_PSK` (64 hex) or a persisted random per-user key under `P2P_DIODE_DIR` (default `~/.st2027_diode/`, 0600, ACL-hardened best effort). | Tests: generated key stable across calls, not the retired constant, environment PSK honored. |
| **A4-11** | Low | `ca_services.py` | Advisory accept loop had no timeout on `accept()`, allowing a connection-starved thread. | `sock.settimeout(30.0)` around `accept`, restored afterwards. | Source inspection; no behavior change for active traffic. |
| **A4-12** | Medium | `p2p_core.py` (STUN) | Attribute parser read declared lengths without bounds checks against the datagram (truncated-datagram parse errors / DoS). | Bounds checks for attribute headers (`pos + 4 + attr_len > len(data)`), minimum body sizes per family (IPv4 8, IPv6 20), malformed datagrams return `None`. | Tests: truncated attribute, lying length, short IPv6 body all `None`; valid IPv4 XOR-MAPPED vector still parses. |
| **A4-13** | Medium | `protocol_manager.py` | Per-identity handshake limiter could be bypassed by rotating identities indefinitely. | Global limiter bucket (120 attempts/min) in addition to the per-identity 10/min; handshake tracker dict pruned and bounded (5000 -> 2500). | Behavioral tests: 11th same-identity attempt raises "Handshake rate limit exceeded"; 121st unique identity raises "Global handshake rate limit exceeded". |
| **A4-14** | High | `secure_key_manager.py` (key store) | File-storage key derived from public host attributes (username/domain/home path), so anyone knowing the host could decrypt stored keys. | `_derive_storage_key` precedence: `P2P_KEY_STORAGE_PASSPHRASE`/`P2P_STORAGE_PASSPHRASE` (PBKDF2-SHA512 600k) > random DPAPI-sealed per-install master KEK (`_get_or_create_storage_master_key`, HKDF-SHA3-512) > lab-only host-attribute fallback with loud warning, prohibited (fail closed) in production; unreadable sealed master raises instead of silently rotating. | Source-contract test (ordering, fail-closed markers, sealed-master path) plus material-separation check between the passphrase and legacy derivations. |
| **A4-15** | Medium | `audit_logging_system.py` | Audit DB PBKDF2 used a hardcoded salt identical in every deployment (cross-install precomputation). | Per-install random 32-byte salt at `P2P_BASE_DIR/.secure_audit_salt` (O_EXCL, 0600); `P2P_AUDIT_LEGACY_SALT=1` reads the historical static salt for migration; persistence failure fails closed. | Tests: salt is per-install, stable across calls, differs from the legacy constant; legacy escape hatch returns the historical value. |
| **A4-15b** | Medium | `audit_logging_system.py` (found during verification) | `os.open`/`os.write` without `O_BINARY` on Windows expands `0x0A` bytes to CRLF, inflating the salt file; the loader accepted any length >= 32, so the first call and later calls derived different keys. | `O_BINARY` added to the create flags; loader validates exactly 32 bytes, deterministically reverses CRLF inflation (recovers the original salt), persists the repair, and preserves longer legacy salts unchanged. | Deterministic worst-case test (all bytes `0x0A`): file is exactly 32 bytes; a manufactured CRLF-inflated legacy file is repaired to the exact original value. |
| **A4-16** | Medium | `libsodium_manager.py` (archive ingestion) | Tar extraction accepted device/FIFO members and used the pre-filter extraction API. | Device/FIFO members rejected before extraction; `filter="data"` used when the runtime provides it. | Test: archive containing a FIFO member is rejected and nothing is extracted. |
| **A4-17** | High | `scripts/run_defense_audit.py` | Master receipt was signed with a fresh throwaway key generated at audit time and discarded: the signature was unverifiable afterwards (self-attestation with no trust anchor). | Persistent TOFU ML-DSA-87 signer at `keys/audit_signer.mldsa87.{sk,pk}` (fail closed on half-present pairs or malformed keys), verify-after-sign probe on the loaded keypair, `signer_pk_sha3_256` recorded in the receipt, `.sig`/`.pub` published alongside. | Consecutive audit runs sign with the same persistent key; receipt signature independently verified against `.pub`; keypair fingerprint matches the recorded digest. |
| **A4-17b** | High | `scripts/run_defense_audit.py` (found during verification) | Same Windows text-mode defect: the 4896-byte ML-DSA-87 secret key was persisted with CRLF inflation (4912 bytes on disk). First run signed from memory; later runs failed with `Invalid SK size` and silently degraded to an unsigned receipt. | `O_BINARY` on creation; load path validates sizes, reverses CRLF inflation, persists the repaired key, and requires a verify-after-sign probe before the keypair is trusted; otherwise fails closed with recovery guidance. | The existing corrupted keypair was repaired in place and verified (probe `True`); two subsequent audit runs produced valid signatures from the recovered key; enterprise-proof test asserts binary-safe write and repair markers. |
| **A4-18** | Medium | `secure_p2p_core/core/orchestrator.py` | Accept loop lacked the connection-rate limiter present in `core/orchestrator.py` (unauthenticated connection floods). | Per-IP accept limiter (5/min) with bounded bookkeeping (512 entries), mirroring the hardened implementation. | Source guard test (limiter markers present). |
| **A4-19** | Medium | `config.py` | `set()` logged full values at debug level, exposing secrets to logs. | `_is_sensitive_key()` used by `set()` to redact values in logs and by `to_dict()` for consistent masking. | Test: sensitive key logged/exported as `[REDACTED]`, non-sensitive value unchanged. |
| **A4-20** | Low | `p2p_core.py` | User input content was written to logs (possible secret/PII capture). | Only the input length is logged. | Source guard (covered by existing suites; log line revised). |
| **A4-22** | Low | `secure_enclave_key_storage.py` | Seed file relied on inherited permissions only. | Explicit 0600 on POSIX and `icacls` restriction on Windows (best effort). | Existing production-tier tests; permission calls are non-fatal. |
| **A4-23** | Low | `.gitignore` | Newly introduced secret artifacts and working directories were not ignored. | Added `.secure_audit_salt`, `.secure_audit_kek.sealed`, `scratch/`, `unsent_messages/`, `diode_station.key/state`. | Test asserts ignore entries present. |
| **A4-24** | Low | `tests/test_nc3_two_terminal_live_transfer.py` | Fixed war-game key committed in a live-transfer test. | Per-run `secrets.token_hex(32)`. | Test asserts the retired constant is absent and per-run generation is used. |
| **A4-25** | Medium | `tactical_data_diode.py` | 32-byte integrity slot held an unkeyed SHA3 of the chunk only (corruption detection, not authentication); a byte-flip in the header passed validation. | Optional pre-shared wire key (`P2P_DIODE_WIRE_KEY` or constructor, 16-64 bytes) replaces the slot with HMAC-SHA3-256 over header+chunk; keyed frames fail authentication on tamper; unkeyed legacy mode still round-trips with a warning; mode mismatch fails closed. | Keyed roundtrip, tamper rejection, keyless-verifier rejection, and legacy unkeyed roundtrip tests. |
| **A4-26** | Low | `destroyer_tactical_p2p.py` | Diode listener staged received data in a predictable millisecond-timestamp file in a shared directory. | `tempfile.mkdtemp()` staging directory with a random `secrets.token_hex(8)` destination filename. | Existing diode suites pass; path derivation is per-run. |
| **F4** | Low (residual) | `secure_transmit_2027.py` (TLS) | Client context keeps `check_hostname=False` by default. | Resolved as documented design trade-off: default outer SNI is the cover domain (`cdn-front.example.net`) and real peer identity is pinned by the inner Noise/PQ handshake, so PKI hostname validation cannot apply on the fronted leg. One-time operator warning added; `P2P_CHECK_HOSTNAME=1` opts into strict checking for direct operation. | Tests `test_secure_transmit_2027.py` pass unchanged; warning is emitted once per process. |

---

## 4. Detailed Notes on Selected Remediations

### 4.1 A4-01/A4-02: Verify-Result Discard in Signature Paths
Both defects shared a failure mode: a verification function was called for its side effects and its boolean result was dropped. The remediations bind the result and fail closed (`raise` on the handshake path; `False` in the verification dictionary). The behavioral tests use real FALCON-1024 keys and demonstrate that bit-flipped or message-mismatched signatures are rejected after the fix.

### 4.2 A4-09: Web Console EAM Custody
The console previously treated fixed-format strings such as officer signatures as sufficient evidence. The endpoint now performs actual ML-DSA-87 dual verification over a canonical byte layout that binds originator, directive, officer identifiers, and a validity window; replay digests are cached per process; and every failure mode reports a distinct non-verified status. The two existing console tests were updated to assert the truthful statuses.

### 4.3 A4-14: Key-Store At-Rest Derivation
Precedence is enforced in code: operator passphrase (PBKDF2-HMAC-SHA512, 600k iterations) over a random DPAPI-sealed per-install master (HKDF-SHA3-512), with the legacy host-attribute derivation retained only as an explicitly logged lab fallback and prohibited in production. An unreadable or malformed sealed master raises rather than rotating, preventing silent orphaning of stored keys.

### 4.4 A4-15b/A4-17b: Windows Text-Mode Key Corruption
Root cause: a file descriptor opened with `os.open` without `os.O_BINARY` is in CRT text mode on Windows; every written `0x0A` byte is stored as `0x0D 0x0A`, and `os.write` still reports the full requested length, so the corruption is silent at write time. Discovery path: the A4-17 regression (re-running the audit) surfaced `Invalid SK size` on the second run; a controlled probe reproduced the inflation (10 newline bytes persisted as 20) and confirmed that `os.fdopen(fd, "wb")` and `Path.write_bytes()` are not affected. Remediation adds `O_BINARY` at both write sites, exact-length validation plus deterministic CRLF-reversal repair on load, and a verify-after-sign probe before a repaired keypair is trusted. The already-corrupted audit signer key in the working tree was repaired in place; the recovered key verifies against the stored public key and has since signed two audit receipts.

### 4.5 A4-17: Audit Receipt Trust Anchor
The receipt signature is now verifiable after the audit finishes: the signer key is persistent (TOFU), its fingerprint is embedded in the receipt, and both signature and public key are published next to the receipt. Independent verification of `defense_master_audit_receipt.json.sig` against `defense_master_audit_receipt.json.pub` succeeds.

---

## 5. Verification Evidence

### New Regression Battery (`tests/test_audit4_remediations_2026_10_17.py`)
```
26 passed in 1.57s
```

### Combined Python Regression Battery
Files: `test_audit4_remediations_2026_10_17.py`, `test_secure_transmit_2027.py`, `test_audit_forensic_remediations.py`, `test_tactical_web_console.py`, `test_network_endpoint_discovery.py`, `test_tactical_data_diode.py`, `test_file_receive_traversal_guard.py`, `test_phase4_ato_redteam_siem.py`, `test_crypto_root_fixes.py`, `test_pqxdh_combiner_v2_kat.py`, `test_combiner_downgrade_guard.py`, `test_nonce_hardening.py`, `test_exploit_regressions.py`, `test_exploit_nonce_state.py`, `test_critical_audit_remediations.py`, `test_pasted_audit_p0_remediations.py`, `test_defensive_audit_targets.py`
```
210 passed, 4 skipped in 58.03s
```
The four skips are platform-gated (Windows symlink privilege x2) or pre-existing archive checks (legacy prototype twins absent x2); none are related to this remediation set.

### Master Defense Audit (`scripts/run_defense_audit.py`)
Two consecutive full runs: `Overall Status : 10/10 SATISFIED - ALL GATES VERIFIED`, with both receipts signed by the persistent TOFU signer `f3c0ae0d...` (ML-DSA-87, 4627-byte signature).

Independent post-run verification (outside the audit script):
```
receipt sig valid: True
signer fp matches pk file: True
```
The `critical_modules.hashes` manifest was refreshed for `secure_transmit_2027.py` to reflect the intentional F4 warning edit; the reproducible-build gate passes.

### Compilation
`python -m py_compile` clean across every edited module, script, and test file.

---

## 6. Residual Risks and Accepted Trade-Offs

1. **TLS hostname validation (F4):** disabled by default for the fronted leg; mitigated by inner-handshake identity pinning and a one-time warning. Hostname checking remains one environment variable away for direct deployments. Callers relying on outer PKI alone for peer naming must set `P2P_CHECK_HOSTNAME=1`.
2. **Diode wire key (A4-25):** authenticated mode requires both ends to share `P2P_DIODE_WIRE_KEY`; without it the frame slot remains corruption-detection only (warning logged). Legacy receivers interoperate in unkeyed mode.
3. **Discovery policy (A4-08):** signed discovery is mandatory in production; lab mode still accepts unsigned broadcasts to preserve interoperability, with a warning.
4. **Legacy audit salt (A4-15):** `P2P_AUDIT_LEGACY_SALT=1` re-enables the historical static salt solely to read pre-migration databases; it is logged loudly and should be unset after migration.
5. **Legacy key-store host-attribute KDF (A4-14):** retained only for non-production hosts without passphrase or DPAPI; production raises.
6. **Pre-existing raw `os.write` sites:** all remaining `os.open`+`os.write` call sites were audited; the two writing binary entropy without `O_BINARY` were fixed here, while sites using `os.fdopen(..., "wb")` or `Path.write_bytes` were empirically confirmed binary-safe. The SIEM chain-key writer already carried the `O_BINARY` fix from a prior cycle.

---

## 7. Files Changed (Code and Tests)

Core modules: `hybrid_kex.py`, `secure_key_manager.py`, `remote_siem_forwarder.py`, `tactical_operator_console.py`, `tactical_web_console.py`, `air_gapped_operation.py`, `decentralized_architecture.py`, `p2p_core.py`, `secure_file_sharing.py`, `destroyer.py`, `destroyer_tactical_p2p.py`, `tactical_data_diode.py`, `protocol_manager.py`, `libsodium_manager.py`, `audit_logging_system.py`, `config.py`, `secure_enclave_key_storage.py`, `ca_services.py`, `secure_transmit_2027.py`, `secure_p2p_core/core/orchestrator.py`.

Scripts and configuration: `scripts/run_defense_audit.py`, `.gitignore`, `critical_modules.hashes`.

Tests: `tests/test_audit4_remediations_2026_10_17.py` (new), `tests/test_tactical_web_console.py`, `tests/test_nc3_two_terminal_live_transfer.py`.

## 8. Reproduction Commands

```
python -m pytest tests/test_audit4_remediations_2026_10_17.py -q
python -m pytest tests/test_audit4_remediations_2026_10_17.py tests/test_secure_transmit_2027.py tests/test_audit_forensic_remediations.py tests/test_tactical_web_console.py tests/test_network_endpoint_discovery.py tests/test_tactical_data_diode.py tests/test_file_receive_traversal_guard.py tests/test_phase4_ato_redteam_siem.py tests/test_crypto_root_fixes.py tests/test_pqxdh_combiner_v2_kat.py tests/test_combiner_downgrade_guard.py tests/test_nonce_hardening.py tests/test_exploit_regressions.py tests/test_exploit_nonce_state.py tests/test_critical_audit_remediations.py tests/test_pasted_audit_p0_remediations.py tests/test_defensive_audit_targets.py -q
python scripts/run_defense_audit.py
python scripts/verify_reproducible_build.py
```
