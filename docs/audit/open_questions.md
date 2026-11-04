# Audit Open Questions & Architectural Decisions

**Audit Run ID:** `RUN-20261104-01`  
**Date:** 2026-11-04  
**Audit Protocol:** Production Engineering and Forensic Verification v5.0  

Consolidated register of technical ambiguities, architectural crossroads, and unresolved engineering questions identified during the repository code audit.

---

## 1. Pre-Existing Uncommitted User Modifications in Working Tree

- **Context:**
  At the commencement of this audit run, the workspace contained 37 tracked files with uncommitted modifications and 17 untracked files from earlier implementation sessions (including IPv6 transport additions, 5 operational pillars tests, and native Rust pipeline extensions).
- **Audit Rule:**
  "Preserve any existing uncommitted user changes: commit them separately on this branch only if I tell you to; otherwise leave them untouched and exclude them from your commits."
- **Question for Repository Owner:**
  Do you want these pre-existing uncommitted modifications committed separately as an initial baseline commit on branch `audit/2026-11-04`, or should they remain untouched and excluded from audit commits?

---

## 2. Hash-Manifest Invalidation in `critical_modules.hashes`

- **Context:**
  `scripts/verify_reproducible_build.py` enforces SHA3-512 pin equality for critical concurrent-edit files. Because `rust_data_plane/src/main.rs` was modified in recent work, its hash has drifted from the pinned value in `critical_modules.hashes`.
- **Audit Rule:**
  "Files that are signed or hashed (*.sig, *.hashes, *.pub, signed config, CBOM): do not edit them silently. If a change invalidates a signature or hash, record it in docs/audit/open_questions.md. Never generate or use a real signing key to re-sign."
- **Status:**
  Recorded here. Updating `critical_modules.hashes` requires explicit human approval before recalculating or re-signing.

---

## 3. Rust 1.99.1 Clippy Compiler Lints

- **Context:**
  Running `cargo clippy --manifest-path rust_data_plane/Cargo.toml --all-targets -- -D warnings` under Rust 1.99.1 reports 6 lints in newly authored native modules (`ffi.rs`, `fragment.rs`, `pipeline.rs`). These do not change wire format or crypto logic.
- **Question for Repository Owner:**
  Should we apply minimal code fixes to resolve these 6 clippy lints so that Gate 1.1 passes with zero warnings?

---

## 4. Prototype Monolith Deprecation & Architectural Convergence

- **Context:**
  `secure_p2p.py` is an extensive monolithic file incorporating user profile handling, cryptography, networking, terminal rendering, and file transfer. A modularized package structure (`core/orchestrator.py`, `messaging/`, `transports/`) exists alongside it, creating twin implementations where changes must be synchronized.
- **Questions for Core Engineering:**
  1. What is the formal milestone for deprecating and retiring `secure_p2p.py` as an operational entry point in favor of `destroyer.py` and `core/orchestrator.py`?
  2. Are any active regression test suites solely dependent on internal methods of `secure_p2p.py`?

---

## 5. Group Messaging Protocol Scalability (Flat Sender-Key vs TreeKEM)

- **Context:**
  The repository contains two distinct group ratcheting implementations:
  - `isolated_group_ratchet.py`: Flat sender-key ratchet ($O(N)$ distribution overhead per member addition).
  - `pq_treekem.py`: Tree-based Key Encapsulation Mechanism ($O(\log N)$ ratchet overhead aligned with IETF MLS).
- **Questions for Core Engineering:**
  1. Is `pq_treekem.py` designated as the sole long-term group key protocol for enterprise and multi-peer channels?
  2. Should flat sender-key distribution be quarantined and restricted to channels with fewer than 10 participants?

---

## 6. Post-Quantum KEM Reserve Agility & Upstream LibOQS Alignment

- **Context:**
  `pqc_algorithms.py:6396` disables HQC-256 by default due to vendored `oqs.dll` binaries predating upstream patches for CVE-2024-54137 and CVE-2025-52473. While pure ML-KEM-1024 is the primary CNSA 2.0 algorithm, HQC-256 is the official NIST backup KEM.
- **Questions for Core Engineering:**
  1. What is the scheduled timeline for recompiling and vendor-signing updated LibOQS binaries (version >= 0.16.1) incorporating upstream lattice security patches?
  2. Should experimental stateful hash-based signatures (`EnhancedXMSS`, `EnhancedLMS`) be retained in the codebase or removed in favor of pure stateless SLH-DSA-256f?

---

## 7. Hardware Attestation Roots & Automated Deployment Provisioning

- **Context:**
  In `tpm_quote.py:38-42`, the table of TPM Endorsement Key root certificates (`EK_ROOTS`) is initialized empty. Production verification enforces strict fail-closed rejection of unverified quotes.
- **Questions for Core Engineering:**
  1. What automated workflow or configuration manifest provisions hardware vendor intermediate and root CA certificates into field nodes before air-gapped activation?
  2. Is AMD SEV-SNP and Intel SGX remote quote verification planned to support air-gapped CRL / VCEK bundle caching?
