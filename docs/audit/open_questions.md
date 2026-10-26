# Audit Open Questions & Architectural Decisions

Consolidated register of technical ambiguities, architectural crossroads, and unresolved engineering questions identified during the repository code audit.

---

## 1. Prototype Monolith Deprecation & Architectural Convergence

- **Context:**
  `secure_p2p.py` is a monolithic 14,886-line file incorporating user profile handling, cryptography, networking, terminal rendering, and file transfer. A modularized package structure (`core/orchestrator.py`, `messaging/`, `transports/`) exists alongside it, creating twin implementations where critical changes must be synchronized.
- **Questions for Core Engineering:**
  1. What is the formal milestone for deprecating and retiring `secure_p2p.py` as an operational entry point in favor of `destroyer.py` and `core/orchestrator.py`?
  2. Are any active regression test suites solely dependent on the internal methods of `secure_p2p.py`?

---

## 2. Group Messaging Protocol Scalability (Flat Sender-Key vs TreeKEM)

- **Context:**
  The repository contains two distinct group ratcheting implementations:
  - `isolated_group_ratchet.py`: Flat sender-key ratchet ($O(N)$ distribution overhead per member addition).
  - `pq_treekem.py`: Tree-based Key Encapsulation Mechanism ($O(\log N)$ ratchet overhead aligned with IETF MLS).
- **Questions for Core Engineering:**
  1. Is `pq_treekem.py` designated as the sole long-term group key protocol for enterprise and multi-peer channels?
  2. Should flat sender-key distribution be quarantined and restricted to channels with fewer than 10 participants?

---

## 3. Post-Quantum KEM Reserve Agility & Upstream LibOQS Alignment

- **Context:**
  `pqc_algorithms.py:6396` disables HQC-256 by default due to vendored `oqs.dll` binaries predating upstream patches for CVE-2024-54137 and CVE-2025-52473. While pure ML-KEM-1024 is the primary CNSA 2.0 algorithm, HQC-256 is the official NIST backup KEM.
- **Questions for Core Engineering:**
  1. What is the scheduled timeline for recompiling and vendor-signing updated LibOQS binaries (version >= 0.16.1) incorporating upstream lattice security patches?
  2. Should experimental stateful hash-based signatures (`EnhancedXMSS`, `EnhancedLMS`) be retained in the codebase or removed in favor of pure stateless SLH-DSA-256f?

---

## 4. Hardware Attestation Roots & Automated Deployment Provisioning

- **Context:**
  In `tpm_quote.py:38-42`, the table of TPM Endorsement Key root certificates (`EK_ROOTS`) is initialized empty. Production verification enforces strict fail-closed rejection of unverified quotes.
- **Questions for Core Engineering:**
  1. What automated workflow or configuration manifest provisions hardware vendor intermediate and root CA certificates into field nodes before air-gapped activation?
  2. Is AMD SEV-SNP and Intel SGX remote quote verification planned to support air-gapped CRL / VCEK bundle caching?

---

## 5. Baremetal seL4 Microkernel Target Integration

- **Context:**
  The `sel4_baremetal/` directory contains native Rust microkit components and Cargo manifests for running on baremetal microkernels. In the current workspace, testing is performed through Python emulation models (`isolated_sel4_appliance.py`, domain models).
- **Questions for Core Engineering:**
  1. What automated build target compiles the native Rust source code against verified seL4 toolchains in the continuous integration environment?
  2. Does the native microkit build enforce identical ring buffer framing to the Python reference twins?

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
