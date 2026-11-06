# High-Assurance Release Governance & Repository Policy

**Document ID:** `ST2027-GOV-2027`  
**Classification:** Defense Production Specification  
**Standard Compliance:** NIST SP 800-161 (C-SCRM), SLSA Build Level 3+, DoD 5210.41M (Two-Person Integrity)  
**Target Maturity:** 100/100 (Full Statutory Release Assurance)

---

## 1. Branch Protection Specification (`main`)

To ensure that the published repository reflects only verified, tamper-proof, and peer-reviewed code, GitHub repository settings for the `main` branch must enforce the following rules:

### 1.1 Mandatory Pull Request Reviews
* **Minimum Reviewers:** At least two (2) independent authorized maintainers from the teams specified in [`CODEOWNERS`](../../CODEOWNERS).
* **Codeowner Approval:** Required for any modifications touching cryptographic cores, TPM anti-rollback routines, key custody, or hash manifests.
* **Dismiss Stale Approvals:** New commits automatically dismiss previous approvals, requiring complete re-review.
* **Require Review from Code Owners:** Mandatory approval from designated cryptographic and hardware teams.

### 1.2 Mandatory Status Checks (Blocking CI Gates)
Every pull request must successfully pass all of the following blocking gates prior to merge:
1. `Cargo Clippy Strict` (`cargo clippy --all-targets -- -D warnings`) — 0 compiler warnings permitted.
2. `Rust Test Suite` (`cargo test`) — 251/251 tests passing across unit, statistical constant-time (`dudect`), and symbolic formal (`kani`) test batteries.
3. `Pytest Suite` (Windows & Ubuntu runners) — 100% test collection and pass rate across all operational modules.
4. `Signed Reproducible Build Verification` (`python scripts/verify_reproducible_build.py`) — SLSA Level 3+ cryptographic receipts verified with ML-DSA-87 anchor.
5. `ProVerif 2.05 Verification` — Formal handshake secrecy and injective correspondence verified.
6. `Hash Manifest Verification` — Bit-for-bit match against `critical_modules.hashes`.

### 1.3 Commit & History Discipline
* **Require Signed Commits:** All commits must be cryptographically signed using GPG, SSH, or hardware PIV smartcards. Unsigned commits are rejected at the remote gateway.
* **Require Linear History:** Merges must be performed via fast-forward rebase or squash-and-merge to maintain clean, auditable history.
* **Block Force Pushes:** `git push --force` is permanently disabled on `main`.
* **Block Deletions:** Deletion of `main` or release tags (`v*`) is forbidden.

---

## 2. GitHub Actions OIDC Least-Privilege Scoping (Remediation for P1-09)

To eliminate broad OIDC identity token generation across unprivileged workflow steps, the CI pipeline enforces strict job-level privilege separation:

```yaml
# Workflow-level permissions: strict read-only default
permissions:
  contents: read
  id-token: none

jobs:
  build_and_test:
    name: Build & Verify
    permissions:
      contents: read
      id-token: none # No OIDC token access during build/test steps
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      - name: Run Cargo & Pytest Tests
        run: |
          cargo test --manifest-path rust_data_plane/Cargo.toml
          pytest tests/ -v

  sign_attestation:
    name: Sign Cryptographic Attestation
    needs: build_and_test
    # OIDC token is restricted EXCLUSIVELY to the isolated attestation step
    permissions:
      id-token: write # Granted ONLY to dedicated signer
      contents: read
    steps:
      - name: Download Built Artifacts
        uses: actions/download-artifact@v4
      - name: Generate Cryptographic Attestation
        run: |
          python scripts/verify_reproducible_build.py
```

---

## 3. Two-Person Integrity (TPI) Release Ceremonies

In compliance with DoD 5210.41M (Two-Person Integrity for Nuclear and Strategic Systems):
1. **Dual Hardware Tokens:** Creation of production release tags requires dual-operator signatures using independent FIPS 140-3 Level 3 hardware security keys (e.g. YubiKey 5 FIPS / Nitrokey HSM).
2. **Offline 3-of-5 Quorum:** X.509 Root CA and CRL modifications require quorum authorization from at least three (3) of five (5) distinct offline ML-DSA-87 custodians in accordance with RFC 9881.
3. **Artifact Retention:** Every production release bundles its binary artifacts, SHA3-512 Merkle root, SPDX/CycloneDX SBOMs, and ML-DSA-87 signed receipts (`compliance_reports/*.sig`) in an immutable, timestamped archive.

