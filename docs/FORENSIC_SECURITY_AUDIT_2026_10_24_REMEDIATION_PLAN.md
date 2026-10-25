# Destroyer-ST2027 Security Remediation Plan

**Audit date:** 2026-10-24  
**Workspace:** `D:\code\Main_projects\p2p\p2p_6_1-26`  
**Status:** Active remediation; not a release approval

## 1. Scope and decision rules

This plan covers defects confirmed by direct source inspection and executable regressions in the current working tree. It preserves pre-existing uncommitted work and does not treat earlier audit documents as proof that a defect is fixed. Cryptographic primitives, protocol construction, state-machine behavior, deployment posture, supply-chain controls, and operational assurance are evaluated separately. A unit-test pass demonstrates only the property exercised by that test; it is not a security certification or evidence of suitability for classified deployment.

The remediation order is based on exploitability and blast radius: authentication-before-state-commit, nonce/counter exhaustion, fail-closed production posture, then protocol and assurance gaps. Every fix requires a focused regression, relevant existing tests, and a recorded residual-risk decision. Findings that require a new protocol, hardware, independent review, or external infrastructure remain open rather than being closed by documentation.

## 2. Confirmed findings and acceptance criteria

| ID | Severity | Evidence in the pre-fix tree | Required remediation | Acceptance evidence |
|---|---|---|---|---|
| R-01 | High | `rust_data_plane/src/group_ratchet.rs::decrypt_group_message` advanced the sender chain and discarded intermediate keys before AES-GCM authentication. The new `forged_frame_does_not_desynchronize_receiver` regression failed: chain state changed after a forged frame. | Derive and authenticate against staged state; insert the staged state only after tag verification. Reject sequence exhaustion without mutation. | Forged, replayed, malformed, and excessive-gap frames leave chain key and sequence unchanged; the subsequent honest frame decrypts. Existing roundtrip tests pass. |
| R-02 | High at the nonce-invariant boundary; impractical counter reachability lowers likely operational exploitability | `rust_data_plane/src/lib.rs::SecureEngine::seal_msg` used `wrapping_add(1)`. Both new exhaustion regressions failed and observed reuse of sequence zero after `u64::MAX`. | Reserve the next sequence with `checked_add` before sealing and refuse exhaustion without emitting a frame or changing state. | `u64::MAX - 1` succeeds exactly once; the next call fails; `u64::MAX` never emits; state remains unchanged on failure. |
| R-03 | Medium | `rust_data_plane/src/ratchet.rs` wrapped `send_seq` and `epoch`, evolved root/chain before fresh-bundle generation, and could return an error after partial mutation. The new counter regression failed. | Preflight both counters; perform encapsulation, fresh generation, and KDF calculations before committing root, chain, counters, and bundle. | Exhaustion and malformed-input tests show no state mutation; normal send/receive still derives equal keys and fresh epochs. |
| R-04 | High | `production_gate.py::_wants` logged an unknown non-empty production value but returned lab mode. `P2P_PRODUCTION=tru` reproduced `production=False`; the old test explicitly pinned fail-open behavior. Numerous modules also parse environment variables independently. | Treat unknown non-empty values as production and latch that decision. Preserve only explicit falsey values as lab mode. Route security-sensitive module gates through the canonical helper and test conflicts and fresh interpreters. | Typo values arm and latch production; explicit falsey/unset values remain lab; either-variable truthy/unknown input wins over the other variable's falsey value; direct module probes match canonical behavior. |
| R-05 | Medium | Rust group AAD concatenated variable-length group and member identifiers without length prefixes. Epoch advancement used unchecked addition and reset only the local sender chain. | Use domain-separated, length-prefixed AAD; check epoch arithmetic; derive all roster sender chains for a coordinated epoch transition. Add a protocol migration note because AAD changes break old-frame compatibility. | AAD collision regression, epoch-exhaustion regression, and multi-member coordinated-rekey roundtrip pass. Documentation must not claim RFC 9420/MLS equivalence. |
| R-06 | Design limitation | Rust group catch-up discards skipped message keys and rejects delayed older frames. The Rust FFI epoch method has no dual-officer authorization despite module-level TPI language. Python and Rust group KDF/AAD formats differ. | Record as open protocol debt unless a complete, authenticated, interoperable group protocol is implemented and reviewed. Narrow unsupported claims. | No claim of MLS, Signal, WhatsApp, or production group-protocol equivalence without a specified wire protocol, authentication/transcript rules, out-of-order behavior, membership semantics, interoperability vectors, and negative tests. |
| R-07 | Assurance gap | Historical reports claim broad test success, but the current Python environment is broken/incomplete. Rust doc-tests previously failed because of a PyO3 artifact/toolchain issue. Local signed receipts do not establish hosted-builder provenance. | Create an isolated workspace test environment; execute targeted and broad non-live tests; separate code failures from environment failures; inspect dependency and secret scans; verify release/provenance scripts independently. | Exact commands, versions, counts, logs, failures, and unexecuted checks are reported. No SLSA L2/L3 claim without an external provenance-verification path. |

## 3. Execution sequence

1. Add and run regressions against the original behavior; retain the observed failures in the audit record.
2. Repair Rust group and PCS state transitions and sequence exhaustion; run the complete Rust library suite.
3. Repair the canonical production gate and its direct call sites; run focused gate tests in-process and in fresh interpreters.
4. Reinspect high-risk Python cryptographic and parser paths for the same state-commit, counter, context-binding, and environment-parsing classes.
5. Establish a reproducible project-local Python test environment without modifying the damaged existing `.venv`.
6. Run targeted then broad non-live Python tests, Rust library tests, doc-tests, Clippy, dependency auditing, secret scanning, and available defense/build gates. Record every environmental limitation.
7. Produce the final evidence report with file/line evidence, Signal/WhatsApp comparison, scores by assurance dimension, unresolved scope, and separate development/pilot and unrestricted-deployment decisions.

## 4. Release boundaries

A green focused suite can support continued development only. It cannot establish resistance to a capable adversary, correct implementation of a standardized group protocol, secure hardware integration, reproducible provenance, or operational suitability for military/classified use. Those require independent cryptographic review, protocol and interoperability vectors, supported-hardware tests, external dependency/provenance verification, threat-model-driven penetration testing, and controlled operational validation. Until then, the unrestricted military/classified deployment decision remains **NO-GO**.
