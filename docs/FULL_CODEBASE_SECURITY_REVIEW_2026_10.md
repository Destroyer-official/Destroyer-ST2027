# Full-Codebase Security Review — October 2026

## 1. Scope

Target: `Destroyer-ST2027` sovereign peer-to-peer system (repository root
`p2p_6_1-26`). Review covered the production Python tree (356 files: 217
non-test modules and 139 test modules), split across 43 parallel review
agents.

In scope:
- Cryptographic core (ML-KEM-1024, ML-DSA-87, hybrid handshake, ratchets,
  threshold cryptography, ZK identity proofs).
- Identity, PKI, certificate authority, key management, TPM/TEE paths.
- Networking, onion routing, relay/DHT, transport anonymity, timing
  resistance, data diode.
- Command-and-control (NC3 EAM, CJADC2 gateway, critical release, group
  ratchet, operator consoles).
- Audit logging, monitoring, SIEM forwarding, supply chain, release
  pipelines, file transfer, update mechanisms.
- Test suite behavior relevant to security contracts (six test batches).

Out of scope (documented drift or separate codebases):
- `notupload/`, `archive/devscripts`.
- `deploy_st2027/` (5 files drift from main tree).
- `secure_p2p_core/` (47 files drift from main tree).
- `rust_data_plane/` (audited continuously by the defense audit gates
  rather than by this review).

## 2. Method

- 43 agents produced per-area reports under `agent_reports/` (about 717 KB).
- Findings were normalized by severity and cross-checked against code
  before any remediation. Only lead-verified findings were patched.
- Severity tally across reports: 14 CRITICAL, 109 HIGH, 255 MEDIUM,
  201 LOW, 49 INFO (about 628 raw items; overlaps possible between
  reports).
- Every candidate fix was validated with targeted pytest runs, the
  combined regression battery, `scripts/verify_reproducible_build.py`,
  and `scripts/run_defense_audit.py`.

## 3. CRITICAL findings and remediation

All 11 distinct CRITICAL issues were fixed and covered by regression tests
in `tests/test_fullreview_critical_remediations.py`.

| ID | Area | Finding | Remediation |
|----|------|---------|-------------|
| C1/C2 | Threshold crypto | Reconstruction accepted share-declared thresholds and index-0 shares, enabling threshold downgrade | Effective threshold is the maximum of manager and share thresholds; share thresholds must agree; index must be an integer of at least 1 |
| C3 | ZK identity | Schnorr challenge was not bound to commitment, key, and domain (Fiat-Shamir forgery) | Challenge is `SHA3-256(IDENTITY_PROOF_DOMAIN || commitment || public_key || challenge)`; proof challenge compared in constant time |
| C4 | PQ certificate authority | Embedded issuer public key acted as its own trust anchor | Only certificates whose issuer equals the local CA name verify |
| C5 | NC3 war key | Deterministic public-constant fallback for the war key | Missing or invalid key material raises `RuntimeError`; env keys must be 32-byte hex; warm-up call sites tolerate the error |
| C6 | Critical release | Caller-asserted RBAC and enroll-then-authorize in one ceremony | RBAC engine `False` now denies; `send_critical` requires a pre-enrolled two-officer authority (`enroll_critical_operator`) |
| C7 | libsodium loader | Windows DLL could be loaded via untrusted sidecar hashes | Windows requires a pinned digest; sidecar files no longer satisfy the gate |
| C8 | Anonymous identity | Onion key material derived from the public key (predictable) | Random Ed25519 key generation |
| C9 | CJADC2 gateway | Release token verified against the package's own embedded key | Signer must be the local gateway key or an explicitly trusted gateway key |
| C10 | Onion routing | Layer keys derived without a local private key; unauthenticated ECDH | Fails closed without a local X25519 private key; 32-byte public-key checks; explicit key setters |
| C11 | Sovereign group ratchet | TPI rekey advanced epochs without officer signatures | Exactly two enrolled officers, dual ML-DSA-87 signatures over a canonical transcript, bounded chain catch-up (1000) |

## 4. HIGH findings remediated in this pass

High findings were triaged into: fixed now, already resolved, documented
decisions, and pending backlog. The per-finding disposition table is in
`docs/review_tmp/high_triage.md`.

Fixed in three batches:
- Batch A: fail-open trust-anchor downgrade in `secure_transmit_2027`;
  undefined TEE exception; nonce-exhaustion fallback; legacy Ed25519 boot
  signatures in production; missing supply-chain manifest handling; relay
  and certificate-cache self-deadlocks.
- Batch B: audit export signatures self-anchored to embedded keys; shadowed
  integer constant-time select; unattended OSV audit failures; paced-console
  EAM two-person-rule claims; unauthenticated diode wire; diode decode crash;
  corrupt quarantine state; stub disposal certification.
- Batch C: symlink-following file reassembly and wipe; covert-channel alerts
  below critical severity were ignored; paced EAM claim in
  `destroyer_tactical_p2p`.

Counts: 53 HIGH findings fixed in this pass (Batches A–C plus the cluster
remediation pass covering audit logging, monitoring, NC3 consoles, CJADC2,
decentralized DHT/relay, destroyer modules, hardware/TEE, PKI identity,
pipeline/release, root-of-trust data, sec-modules, secure P2P, secure
transmit, security tiers/agility, supply chain, transport, core orchestrator,
air-gap discovery, memory primitives, messaging, and the network TPM-quote
path). A second, coverage-driven pass re-extracted all 85 HIGH headings from
the 43 agent reports and mapped each to the code it names; the 15 headings
that still referenced unmodified code were fixed as well. One HIGH cluster
was verified as already resolved in production posture, and one documented
decision retains a pinned lab behavior.

## 5. Verified pre-existing controls and documented decisions

- Minimal RBAC is deny-by-default in every environment; in production,
  `is_rbac_strict()` auto-enables and explicit opt-out is ignored
  (`tests/test_wave8_regressions.py`).
- `production_gate` treating unrecognized production spellings as
  non-production is pinned by `tests/test_production_gate.py`. The accepted
  truthy set was broadened so common operator spellings arm the gate; genuine
  typos still fail open and are logged at CRITICAL level. The other
  production detector (`utils/message_caps.prod_strict_on`) now delegates to
  the canonical gate instead of re-implementing it.
- `dependency_security_verifier._verify_file_integrity` no longer accepts an
  unpinned dependency in production; in lab the missing pin is logged as a
  warning because PyPI distributions ship no sidecar signature to pin
  against.

## 6. Residual backlog

No triaged HIGH finding remains unpatched. The per-finding disposition table,
including the fix applied to every backlog item, is in
`docs/review_tmp/high_triage.md`. Items outside the HIGH set (MEDIUM, LOW,
INFO) were reviewed for truthfulness in their documentation and remain
tracked separately.

## 7. Verification evidence

- `tests/test_fullreview_critical_remediations.py`: 35 passed, 2 skipped
  (POSIX-only symlink tests) after Batch C.
- Combined regression battery (29 files): 405 passed, 7 skipped.
- Targeted suites after Batch C: 62 passed, 2 skipped.
- `scripts/verify_reproducible_build.py`: PASSED after refreshing the
  `secure_transmit_2027.py` entry in `critical_modules.hashes` for the
  reviewed trust-anchor change (only pinned file edited in this pass).
- `scripts/run_defense_audit.py`: 10/10 SATISFIED (Gates 1 through 9,
  including supply chain pinning and documentation truth checks).

## 8. Limitations

- Review coverage is agent-report based; heuristic/table HIGH items that
  were not in canonical form are tracked separately and may need individual
  extraction.
- Drift directories listed in Section 1 were not reviewed.
- The backlog items above were confirmed by report and code spot-checks but
  were not all independently reproduced with exploits.
- Test runs were executed on Windows; POSIX-only tests (symlink refusal)
  skip locally and are expected to execute in POSIX CI.
