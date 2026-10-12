# liboqs pin (oqs.dll) — version, hashes, update procedure

Additive pin record. CI-safe: `adversarial-gates` checks the floor
(≥ 0.16.0) and SKIPs the native assert when the binary is absent from
the runner (e.g. Windows `oqs.dll` on `ubuntu-latest`).

## Current pin

| Field | Value |
|---|---|
| Vendored binary | `oqs.dll` (repo root, Windows; `liboqs_wrapper.py` falls back to `liboqs.so` on Linux) |
| Embedded version string in binary | `0.14.1-dev` (printable string adjacent to `system`/`OpenSSL` alg table; `OQS_version` export present) — BELOW FLOOR, fail-closed until rebuilt |
| SBOM-declared version | `0.16.0` target (`generate_production_sbom.py:259`, `supply_chain_security.py:1112`, `compliance_reports/{spdx,cyclonedx}_sbom.json`) |
| Verifier floor (`dependency_security_verifier.py` `oqs.dll.min_version`) | `0.16.0` (only 0.16.0 supported upstream; <0.16 unsupported) |
| Verifier upgrade target | `0.16.0` |
| Blocked algorithms until rebuild | `HQC-128`, `HQC-192`, `HQC-256`, `XMSS-SHA2_10_256`, `XMSS-SHA2_16_256`, `XMSSMT-*` (see verifier `blocked_algorithms` + `triple_hybrid_kem.py` allowlist) |
| Allowed / exercised paths | `Classic-McEliece-8192128f`, `ML-KEM-1024`, `ML-DSA-87` (+ `SLH_DSA_PURE_SHAKE_256f`, Falcon-1024 via wrapper) |

> Note (hardened 2026-10-10): the vendored `oqs.dll` embeds
> `0.14.1-dev` which is BELOW the `0.16.0` floor (upstream supports only
> 0.16.0; CVE-2024-54137/CVE-2025-52473 HQC + CVE-2026-44518/CVE-2026-46344
> XMSS fixed in 0.16.0). Treat `0.16.0` as the **minimum supported**;
> the CI pin check asserts `>= 0.16.0` via `OQS_version()` when
> the native lib is present, else via the SBOM/verifier floor. The
> vendored binary MUST be rebuilt at `0.16.0` from an official release
> (never a -dev snapshot); until then HQC/XMSS stay refused and
> production loads fail closed on version check (see Update procedure).

## Hashes (measured 2026-09-18, `oqs.dll`, 3030016 bytes)

```
size:     3030016
sha256:   ab7f7005df004d0168b23afa8b2fba41a2b2c0c60a8a555abc1b6be56846d4da
sha512:   995ed25ed9345be0bb1f6e1ba6dfd90ad804af4fe877cc3b74dbf38b7d8634dbdf7a9fb9326dc3881af1838ef14126d483065e02dde1302f49980c6ac254581e
sha3_256: 79b3fdbfe73595115358047806f5d68c8fe237466e76e9e582d1469fa30d60b3
sha3_512: 7c6801cd0faf6aad077bf11220f98b0b171bf23970c6d2fc918a36004b7da8984e635846cfcba7020220579dfb5e42b4ea3a8fee12d5f05f2dc9062f1d2292b1
```

Sidecars (repo root, Ed25519):

| File | Size | Purpose |
|---|---|---|
| `oqs.dll.sig` | 64 bytes | Ed25519 signature over `oqs.dll` bytes (verified by `dependency_security_verifier.py`) |
| `oqs.dll.pub` | 116 bytes (PEM `MCowBQYDK2VwAyEA…`) | Trust anchor for the above |
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
The workflow builds from the official tag under MSVC, asserts
`OQS_version() >= tag` (fail-closed), and records hashes for the table.

1. Build liboqs at the target tag (goal: `0.16.0`) from upstream
   <https://github.com/open-quantum-safe/liboqs> with only the
   allowlisted algs enabled; record commit SHA + build flags.
   (Or dispatch `oqs-rebuild.yml` and use its artifact.)
2. Replace `oqs.dll` (and `liboqs.so` for Linux CI if shipped), then
   regenerate sidecars:
   - `oqs.dll.hashes` ← fresh `{sha512, sha3_512, size}` (keep `size` field).
   - `oqs.dll.sig` ← Ed25519-sign the new bytes; keep `oqs.dll.pub` as the
     matching anchor (rotate only with a documented ceremony).
3. Bump the declared version in **all three** places (they must agree):
   `generate_production_sbom.py` (`dlls` list),
   `supply_chain_security.py` (`add_native_dependencies`),
   `dependency_security_verifier.py` (`oqs.dll.min_version`, and lower/
   clear `blocked_algorithms` only after the HQC/XMSS fixes land).
4. Regenerate + re-sign SBOMs: `python generate_production_sbom.py`
   (ML-DSA-87 `.mldsa87.sig`/`.pub` siblings), then
   `python scripts/verify_reproducible_build.py`.
5. Re-enable HQC/XMSS paths **only** if the rebuilt version contains the
   upstream fixes (CVE-2024-54137, CVE-2025-52473, CVE-2026-44518 /
   CVE-2026-46344 per verifier comment); otherwise keep them blocked and
   keep `upgrade_target` open.
6. Update this file's table + hashes; CI (`adversarial-gates` liboqs pin
   check) asserts `>=` floor and fails closed only when a present version
   is below floor — missing native lib stays SKIP exit 0.

## RIC / masking backport tracking

Upstream hardening backports tracked for the `0.16.0` rebuild (masking /
randomized-integrity-check fixes; advisory until vendored):

- <https://eprint.iacr.org/2025/2009> — RIC/masking backport tracking (2025/2009).
- <https://eprint.iacr.org/2026/924> — RIC/masking backport tracking (2026/924).

Status: **FAIL-CLOSED below floor** — `oqs.dll` remains a `0.14.1-dev`
binary below the `0.16.0` floor with HQC/XMSS disabled and version-gated.
Rebuild at official `0.16.0` + re-verification above is REQUIRED before
production trust. See also
`dependency_security_verifier.py` header comment and
`generate_production_sbom.py verify_sbom_offline TODO(rekor)` for the
Cosign/Rekor anchoring plan.

## Runtime enforcement (2026-10-11 hardening — floor is now REAL)

The sidecar/SBOM checks verify INTEGRITY, never the live binary's version,
so `verify_liboqs_native_version()` (`dependency_security_verifier.py`)
queries `OQS_version()` and compares the single-sourced floor, enforced at
`liboqs_wrapper.py` load time:

| Mode | Below-floor binary (`0.14.1-dev` today) |
|---|---|
| production/TS (`P2P_PRODUCTION`/`SECURE_P2P_PRODUCTION=1`/`P2P_TS_MODE`) | `ImportError` — Python PQ path dead until rebuild (verified: exit 1, `FATAL … production/TS load refused`) |
| lab | `CRITICAL` log + `LIBOQS_BELOW_FLOOR=True`, load continues (ML-KEM/ML-DSA paths unaffected by the fixed HQC/XMSS CVEs; HQC/XMSS legs refused regardless) |

Strict-mode semantics are IDENTICAL to the orchestrator's canonical check
(`secure_transmit_2027.py:558`) by design — uniform mode perception, no
surprises. KNOWN GAP (P1, pre-existing, repo-wide): most `SECURE_P2P_PRODUCTION`
gates test `== "1"` while CI sets `"true"`, so CI's "prod" selftest runs lab
paths. Normalize to one 4-value helper repo-wide AND set CI to `"1"` (or vice
versa) — a maintainer decision with test implications; do NOT fix piecemeal.

## Evidence (2026-10-11, this machine)

* `cargo audit` (RustSec DB 2026-10-09, 1296 advisories, 105 locked crates):
  **0 vulnerabilities, 0 warnings** — pins `ml-dsa 0.1.1` (covers
  CVE-2026-22705 + hint-dup), `ml-kem 0.3.2`, `p384` 0.14.0 all clean.
* Bandit on `liboqs_wrapper.py` + `dependency_security_verifier.py`:
  **0 issues** (4 justified `nosec` suppressions).
* Rebuild BLOCKED on this box: no C toolchain (`cl`/`gcc`/`clang`),
  no CMake, no Visual Studio — rebuild must happen on a build host or in
  CI (ubuntu runner + `apt install cmake ninja-build gcc`), then follow
  the update procedure above. Do NOT vendor another `-dev` snapshot:
  rebuild from the official `0.16.0` tag only.

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
