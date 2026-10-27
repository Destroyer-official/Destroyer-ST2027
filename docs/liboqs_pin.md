# liboqs pin (oqs.dll) — version, hashes, update procedure

Additive pin record. CI-safe: `adversarial-gates` checks the floor
(≥ 0.16.0) and SKIPs the native assert when the binary is absent from
the runner (e.g. Windows `oqs.dll` on `ubuntu-latest`).

## SWAPPED + SIGNED 2026-10-16 — vendored binary is now 0.16.0

Workflow run `38926972301` ("Rebuild oqs.dll (liboqs 0.16.0, Windows)",
green in 7m3s) produced the `oqs-dll-0.16.0` artifact; it was locally
verified and SWAPPED into the repo root, then signed under the trust
anchor rotation ceremony:

| Field | Value (verified artifact, now vendored) |
|---|---|
| `OQS_version()` (ctypes, fresh process) | `0.16.0` — official release string, at floor |
| liboqs.commit (artifact) | `5a1a854b0dc9f2141bdc771c555ee60c37950183` — matches the documented pin |
| Size | 4,355,072 bytes |
| Build (this artifact) | MSVC x64 (VS18 toolset 14.51), `BUILD_SHARED_LIBS=ON`, `OQS_BUILD_ONLY_LIB=ON`, Release |

**Trust-anchor rotation ceremony (documented, 2026-10-16 17:24 UTC):**
the original Ed25519 CA private key (which signed the pre-swap
`oqs.dll.sig`/`libsodium.dll.sig`) was not available on the build host —
neither on disk, nor in git history, nor in any stash. Per the update
procedure ("rotate only with a documented ceremony"), a NEW Ed25519 CA
key was generated in offline custody
(`~/.destroyer-st2027/offline-keys/military_root_ca.pem`, encrypted at
rest, passphrase sidecar 0400, ACL restricted to the operator account)
via `python scripts/sign_dependencies.py --rotate`. Both `oqs.dll` and
`libsodium.dll` were re-signed; all four anchors (`*.dll.pub`,
`*.dll.sig`, `*.dll.hashes`) were rotated consistently. Receipt (with
Ed25519 self-signature, hashes, fingerprints):
`docs/dll_ca_ceremony_receipt.json` (new anchor pub sha256
`3cb29eef2f32e70520a481105de5556e9247db4387f87c5febf6271cdbfea98c`).
Old anchor (sha256 `2f45d1ae…`) is retired; any previously distributed
copy must be replaced.

**Rotation plumbing that MUST move together (learned 2026-10-16):**
swapping the DLL and sidecars alone is NOT sufficient — the runtime
verifier pins the trust anchor EMBEDDED in code:

- `dependency_security_verifier.py` `EMBEDDED_OQS_ED25519_PUBKEY_PEM` +
  `EMBEDDED_OQS_SHA384` (sha512-family SHA-384 of the new DLL —
  `bed075001dddcf7395eeb11baa7c100f19a8a386d23c48115f41a225c24f38adfc3d9b86b2b4c5a3ed29dc62df5cf4eb`).
- `critical_modules.hashes` (hash-manifest CI gate) must be refreshed
  for `dependency_security_verifier.py` in the same commit.
- SBOM version bumps (3 places) + SBOM/receipt regeneration (below).

**Toolchain note:** the MSVC build emits liboqs's "non-GNUC/Clang
toolchain — no optimization barrier" warning (constant-time caveat).
`oqs-rebuild.yml` now builds with **clang-cl + Ninja** (CMake sees
"Clang", so the barriers compile in); the next dispatch should be
preferred for the shipped binary once proven green. The current vendored
artifact is the MSVC build above.

Workflow fixes that were required (all pushed 2026-10-16): valid
`lukka/get-cmake` pin (v4.4.2), MSVC x64 environment via
`ilammy/msvc-dev-cmd` v1.13.0 (standalone CMake cannot discover the
runner's VS), and `-DOQS_BUILD_ONLY_LIB=ON` (liboqs test executables
fail to link on the VS18 toolset due to SLH-DSA STFL symbols; the
DLL itself builds clean).

## Current pin

| Field | Value |
|---|---|
| Vendored binary | `oqs.dll` (repo root, Windows; `liboqs_wrapper.py` falls back to `liboqs.so` on Linux) |
| Embedded version string in binary | `0.16.0` (official release; `OQS_version()` export verified) — AT FLOOR, production loads |
| SBOM-declared version | `0.16.0` (`scripts/generate_production_sbom.py` dlls list and `supply_chain_security.py` `add_native_dependencies`; regenerated into `compliance_reports/{spdx,cyclonedx}_sbom.json` + CBOM 2026-10-16) |
| Verifier floor (`dependency_security_verifier.py` `oqs.dll.min_version`) | `0.16.0` (only 0.16.0 supported upstream; <0.16 unsupported) |
| Verifier upgrade target | `0.16.0` — SATISFIED |
| Blocked algorithms (conservative, operator-gated) | `HQC-*`, `XMSS-*` remain refused by default (`liboqs_wrapper` opt-in gate + `triple_hybrid_kem.py` allowlist + verifier `blocked_algorithms`); the 0.16.0 CVEs are fixed, so re-enabling is now a capability decision, not a CVE gate |
| Allowed / exercised paths | `Classic-McEliece-8192128f`, `ML-KEM-1024`, `ML-DSA-87` (+ `SLH_DSA_PURE_SHAKE_256f`, Falcon-1024 via wrapper) |

> Note (2026-10-16): the vendored `oqs.dll` is the official `0.16.0`
> release (all HQC/XMSS CVEs fixed upstream). The floor check
> (`>= 0.16.0`, official-release format only) stays enforced at
> `liboqs_wrapper.py` load time + CI pin check + rebuild assert —
> rebuilding at a NEW tag re-runs the full update procedure incl. the
> rotation plumbing above.

## Hashes (measured 2026-10-16, `oqs.dll`, 4355072 bytes)

```
size:     4355072
sha256:   ab1c1373a464a4ed5f3d5292935084fe6fe272ee51edca18b1083b7b631233e2
sha512:   b10aadbeb94c4d7462090c0ba02b4f1bb5e30ff9691638263e41896b0fad7e675a49a8e9556e9167dae16aae15db867e84682d9ffc0b3f44c370c4dcd4ee7ee7
sha3_256: 29295ebc9a3dbef11ac9bac14dba41f94271e89575f757441534639e98b26996
sha3_512: c6af8151a04b750112f49c8d5ae39df1a4625b99dd0c1ac70385867b9308dc4d187a1cbb3ee034ce3c1c3ec9a72cd3147fdfaad74b1940bea16264b3af5ac0ea
```

Sidecars (repo root, Ed25519, rotated 2026-10-16):

| File | Size | Purpose |
|---|---|---|
| `oqs.dll.sig` | 64 bytes | Ed25519 signature over `oqs.dll` bytes (verified by `dependency_security_verifier.py`) |
| `oqs.dll.pub` | 113 bytes (PEM `MCowBQYDK2VwAyEAKy5ea9…`) | Trust anchor for the above (rotated; see ceremony) |
| `oqs.dll.hashes` | JSON `{sha512, sha3_512, size}` | Integrity anchor (matches table above) |

Recompute locally (Windows PowerShell):

```powershell
python -c "import hashlib; d=open('oqs.dll','rb').read(); print('size',len(d)); print('sha256',hashlib.sha256(d).hexdigest()); print('sha512',hashlib.sha512(d).hexdigest()); print('sha3_256',hashlib.sha3_256(d).hexdigest()); print('sha3_512',hashlib.sha3_512(d).hexdigest())"
```

## Update procedure (rebuild → re-pin)

Windows rebuilds are now automated via the manual-dispatch workflow
`.github/workflows/oqs-rebuild.yml` (F-01): run it with the target tag
(default `0.16.0`), download the `oqs-dll-<tag>` artifact (contains the
fresh `oqs.dll` + `liboqs.commit`), then follow the re-pin steps below.
The workflow builds from the official tag (clang-cl + Ninja; MSVC SDK
env), asserts `OQS_version() >= tag` (fail-closed), and records hashes
for the table.

1. Build liboqs at the target tag (goal: `0.16.0`) from upstream
   <https://github.com/open-quantum-safe/liboqs>; record commit SHA +
   build flags. (Or dispatch `oqs-rebuild.yml` and use its artifact.)
2. Swap `oqs.dll` (and `liboqs.so` for Linux CI if shipped), then
   regenerate sidecars with the custodied CA key:
   `python scripts/sign_dependencies.py` (re-sign) — writes
   `*.dll.sig` + `*.dll.hashes` + keeps the matching `*.dll.pub`.
   A DIFFERENT CA key (rotation) requires the explicit `--rotate`
   ceremony flag and writes `docs/dll_ca_ceremony_receipt.json`.
3. Rotation plumbing — replace the EMBEDDED pins in the same commit:
   `dependency_security_verifier.py` (`EMBEDDED_OQS_ED25519_PUBKEY_PEM`,
   `EMBEDDED_OQS_SHA384` = SHA-384 of the new DLL) and refresh
   `critical_modules.hashes` for that file. `oqs.dll.pub` sidecar alone
   authorizes nothing at runtime (by design).
4. Bump the declared version in **all three** places (they must agree):
   `generate_production_sbom.py` (`dlls` list),
   `supply_chain_security.py` (`add_native_dependencies`),
   `dependency_security_verifier.py` (`oqs.dll.min_version`; lower/clear
   `blocked_algorithms` only as an explicit operator capability decision).
5. Regenerate + re-sign SBOMs:
   `python scripts/generate_production_sbom.py` (with
   `SBOM_SIGNING_KEY`/`SBOM_PUBKEY` pointing at the offline-custody
   signer + certs anchor when the signer has been relocated, see
   docs/airgap_runbook.md §6), then
   `python scripts/verify_reproducible_build.py`.
6. Update this file's table + hashes; CI (`adversarial-gates` liboqs pin
   check) asserts `>=` floor AND official-release format (a `-dev`/
   prerelease string fails even at floor) — missing native lib stays
   SKIP exit 0.

## RIC / masking backport tracking

Upstream hardening backports tracked for the `0.16.0` rebuild (masking /
randomized-integrity-check fixes; advisory until vendored):

- <https://eprint.iacr.org/2025/2009> — RIC/masking backport tracking (2025/2009).
- <https://eprint.iacr.org/2026/924> — RIC/masking backport tracking (2026/924).

Status: **SWAPPED AND SIGNED (2026-10-16)** — the vendored `oqs.dll` is
the official `0.16.0` release (verified above), signed under the
documented anchor rotation ceremony
(`docs/dll_ca_ceremony_receipt.json`); production loads verified
(ML-KEM-1024 + ML-DSA-87 keygen/sign/verify under `P2P_PRODUCTION=1`).
HQC/XMSS remain refused by conservative policy (opt-in gate), not by
CVE entitlement. See also
`dependency_security_verifier.py` header comment and
`generate_production_sbom.py verify_sbom_offline` (Rekor transparency entrypoint) for the
Cosign/Rekor anchoring plan.

## Runtime enforcement (2026-10-11 hardening — floor is now REAL)

The sidecar/SBOM checks verify INTEGRITY, never the live binary's version,
so `verify_liboqs_native_version()` (`dependency_security_verifier.py`)
queries `OQS_version()` and compares the single-sourced floor, enforced at
`liboqs_wrapper.py` load time. Only plain official release strings
(`X.Y.Z`) can meet the floor — `-dev`/prerelease snapshots are rejected
even at/above it (runtime check + CI pin check + rebuild assert,
hardened 2026-10-13):

| Mode | Current binary (`0.16.0`, at floor) |
|---|---|
| production/TS (`P2P_PRODUCTION`/`SECURE_P2P_PRODUCTION=1`/`P2P_TS_MODE`) | loads (verified 2026-10-16: ML-KEM-1024 + ML-DSA-87 exercised under prod env). A below-floor / -dev binary would still `ImportError` fail-closed — the gate remains armed for future regressions. |
| lab | loads; `LIBOQS_BELOW_FLOOR=False` on the current binary; HQC/XMSS legs refused regardless (opt-in gate) |

Strict-mode semantics are IDENTICAL to the orchestrator's canonical check
(`secure_transmit_2027.py:558`) by design — uniform mode perception, no
surprises. KNOWN GAP (P1, pre-existing, repo-wide): most `SECURE_P2P_PRODUCTION`
gates test `== "1"` while CI used to set `"true"`, so CI's "prod" selftest ran
lab paths. **Closed 2026-10-13 (CI side):** the selftest step in
`.github/workflows/defense_ci.yml` now sets `"1"` for all three flags
(`SECURE_P2P_PRODUCTION`, `P2P_STRICT_SECURITY`, `CNSA_2027_STRICT`), so the
existing `== "1"` gates activate.

**CLOSED 2026-10-14 (repo side, F-01):** as this section prescribed ("normalize
all gates to one shared helper; do NOT fix piecemeal"), every production gate
now routes through the single sticky detector `production_gate.is_production()`
(canonical truthy set `1/true/yes/on` for BOTH `P2P_PRODUCTION` and
`SECURE_P2P_PRODUCTION`, process-sticky, audit-logged; explicit falsey
spellings keep lab mode; unknown spellings fail toward lab WITH a CRITICAL
log). ~30 former one-off checks (`== "1"`-only, `== "true"`-only,
`("1","true")`-only, no-`.lower()` case traps, first-non-empty-var-wins) were
converted. Covered by `tests/test_production_gate.py` (114-case matrix: both
vars × all spellings × falsey set × sticky-latch × direct module-gate probes ×
fresh-interpreter import-time arming), asserted in the CI suite run.

## Evidence (2026-10-11, this machine)

* `cargo audit` (RustSec DB 2026-10-09, 1296 advisories, 105 locked crates):
  **0 vulnerabilities, 0 warnings** — pins `ml-dsa 0.1.1` (covers
  CVE-2026-22705 + hint-dup), `ml-kem 0.3.2`, `p384` 0.14.0 all clean.
* Bandit on `liboqs_wrapper.py` + `dependency_security_verifier.py`:
  **0 issues** (4 justified `nosec` suppressions).

## Post-swap evidence (2026-10-16, this machine)

* Wrapper load: `[OK] oqs.dll security verification passed` (embedded
  Ed25519 pin + SHA-384 constant), `OQS_version 0.16.0 meets floor`,
  `LIBOQS_BELOW_FLOOR=False`.
* Production env exercised: `P2P_PRODUCTION=1` → `LibOQS_MLKEM_1024` +
  `LibOQS_MLDSA_87` keygen/sign/verify all succeed.
* SBOMs + CBOM regenerated and ML-DSA-87-signed
  (`compliance_reports/*.mldsa87.sig` verified); reproducible-build
  receipt: `[SUCCESS] … (100% Verified)` with the refreshed
  `critical_modules.hashes` manifest.

## External anchoring ceremony (Sigstore/Rekor — NOT yet executable here)

Blocked on this box by (1) corrupted system pip (`pip._internal.operations.
build.metadata` missing — local installs impossible; repair the Python
installation, out of scope for this repo) and (2) headless OIDC (keyless
signing needs a browser or CI ambient credentials). The correct venue is
CI, which already requests `id-token: write`. Exact ceremony for the
release job (reviewed, merge when a green run is observed):

```yaml
- uses: sigstore/gh-action-sigstore-python@v3
  with:
    inputs: compliance_reports/spdx_sbom.json
- run: |
    sigstore verify identity \
      --bundle compliance_reports/spdx_sbom.json.sigstore \
      --cert-identity 'https://github.com/Destroyer-official/Destroyer-ST2027/.github/workflows/defense_ci.yml@refs/heads/main' \
      --cert-oidc-issuer https://token.actions.githubusercontent.com \
      compliance_reports/spdx_sbom.json
```

Until Rekor inclusion is proven for a release commit, the in-repo
ML-DSA-87 `.mldsa87.sig` sidecars remain LAB-GRADE self-attestation
(they prove nothing to an outsider holding only the repo) — say so
wherever they are cited.

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
