# Audit Architectural & Protocol Proposals

**Audit Run ID:** `RUN-20261104-01`  
**Date:** 2026-11-04  
**Audit Protocol:** Production Engineering and Forensic Verification v5.0  

This document catalogs proposed architectural, protocol, wire-format, and cryptographic changes that exceed the scope of defect fixes. Under the audit charter, no cryptographic algorithms, wire formats, protocol state machines, or security policies are modified without prior explicit written authorization from the repository owner.

---

## Proposal 1: Unified Zero-Gap Wire Protocol Formal Specification

### Summary
Document the Zero-Gap Multi-Layer Defense Pipeline wire format (prefixed by magic `ZG` and version `ZGDP-V1`) in an authoritative formal specification under `docs/specs/ZERO_GAP_WIRE_PROTOCOL.md`.

### Technical Details
- **Current State:**
  Implemented in `rust_data_plane/src/pipeline.rs` and consumed by `test_real_uses_dual_terminal_ipv6.py`.
- **Wire Framing:**
  - 2-byte Magic: `b"ZG"` (`0x5A`, `0x47`)
  - 7-byte Version: `b"ZGDP-V1"`
  - 1-byte Message Type: `0x01` (Msg), `0x02` (File), `0x03` (NC3 Directive)
  - 8-byte Monotonic Sequence: uint64 big-endian
  - 8-byte Epoch Counter: uint64 big-endian
  - $L$-byte Quantized and Whitened Payload ($L \in \{256, 512, 1024, 2048, 4096, 8192, 16384\}$ bytes)
  - 16-byte Outer AEAD Authentication Tag (AES-256-GCM)
- **Security Rationale:**
  Provides complete formal specification for interoperability audits and third-party implementation verifications.

---

## Proposal 2: Upstream LibOQS Upgrade & HQC-256 Agility Re-Enactment

### Summary
Update vendored `oqs.dll` from upstream Open Quantum Safe to release >= 0.16.1 once upstream publishes CVE-remediated builds for HQC-256.

### Technical Details
- **Current State:**
  `pqc_algorithms.py:6396` disables HQC-256 due to CVE-2024-54137 and CVE-2025-52473.
- **Proposed Action:**
  1. Build `oqs.dll` from upstream source with MSVC 2022 on an isolated builder.
  2. Compute SHA-384 and SHA3-512 integrity hashes.
  3. Sign the binary using the release ceremony private key.
  4. Update `oqs.dll.hashes` and `critical_modules.hashes`.
  5. Re-enable HQC-256 as secondary backup KEM in `pqc_algorithms.py`.

---

## Proposal 3: Hash Manifest Re-Baseline for Production Release

### Summary
Update `critical_modules.hashes` to incorporate the verified SHA3-512 digest of `rust_data_plane/src/main.rs` once all review branch commits are finalized and approved.

### Technical Details
- **Current State:**
  `scripts/verify_reproducible_build.py` flags hash drift on `rust_data_plane/src/main.rs`.
- **Proposed Action:**
  Following human review of the audit branch, execute `python scripts/sign_dependencies.py` to regenerate the authoritative hash manifest and sign it with the project release key.

