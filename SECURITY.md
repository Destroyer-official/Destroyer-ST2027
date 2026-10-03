# Security Policy & Vulnerability Disclosure

## 1. Research & Evaluation Scope

**Sovereign Transmit 2027 (ST2027)** is an open reference implementation, mathematical specification, and automated verification testbed for post-quantum defense communication protocols.

### Evaluation Boundaries & Non-Claims
- **No Third-Party Government Accreditation:** Automated tests, OSCAL documents, and SSDF attestations are self-attestations and reference testbeds. They do **not** constitute an official government Authority to Operate (ATO), Common Criteria EAL4+ certificate, or NIST CMVP FIPS 140-3 laboratory validation.
- **Physical vs. Software Gatekeeper:** User-space software acts as an algorithmic enforcement engine and fail-closed gatekeeper. Physical FIPS 140-3 Level 3/4 enclosures, TEMPEST SDIP-27/28 attenuation, and physical optical data diodes require certified hardware.
- **Synthetic Test Fixtures:** All cryptographic keys, certificates, nodes, and military message schemas (e.g., CoT, TPI, EAM) in this repository are **100% synthetic, unclassified, and executed in local test harnesses**.

---

## 2. Supported Versions

| Version | Supported | Security Maintenance |
| :--- | :--- | :--- |
| `0.2.x` (ST2027 Target) | Yes | Active cryptographic hardening & CNSA 2.0 alignment |
| `< 0.2.0` (Legacy prototype) | No | Quarantined in `archive/`; deprecated |

---

## 3. Reporting a Vulnerability

We welcome coordinated vulnerability disclosures, cryptographic cryptanalysis, and code review from independent researchers and government evaluators.

### How to Report:
1. **Confidential Reporting:** Do **not** open a public GitHub issue for suspected cryptographic flaws, memory corruption vulnerabilities, or authentication bypasses.
2. **Submit Details via GitHub Security Advisories:** Use the [GitHub Security Advisory Reporting Tool](https://github.com/Destroyer-official/Destroyer-ST2027/security/advisories/new) to submit your findings privately.
3. **Information to Include:**
   - Detailed description of the vulnerability or cryptographic weakness.
   - Proof-of-concept (PoC) code or reproducible test script.
   - Impact assessment (e.g., key compromise, replay attack, side-channel leakage, denial-of-service).
   - Any suggested mitigations.

### Response Timelines:
- **Initial Response:** Within 48 hours.
- **Triage & Reproduction:** Within 5 business days.
- **Remediation & Patch Release:** Priority based on CVSS / severity rating, coordinated prior to public disclosure.

---

## 4. Cryptographic Posture & Policy

- **Primary Baseline:** Strict NSA CNSA Suite 2.0 algorithms:
  - FIPS 203 ML-KEM-1024
  - FIPS 204 ML-DSA-87
  - AES-256-GCM (NIST SP 800-38D)
  - SHA-384 / SHA-512 (FIPS 180-4)
- **Classical Hybrid Leg:** NIST P-384 ECDH strictly as an auxiliary defense-in-depth hedge per IETF RFC 10024.
- **Memory Safety:** Key custody and framing logic are transitioning to native Rust (`rust_data_plane`) with `zeroize`, `mlock`, and constant-time execution.
