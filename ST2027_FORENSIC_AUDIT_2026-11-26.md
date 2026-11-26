# Forensic Security Audit — Destroyer-ST2027

**Audit date:** 26 November 2026  
**Audit target:** `D:\code\Main_projects\p2p\p2p_6_1-26`  
**Committed baseline:** `d21c280d3e30a09cc799ebe2661a33e491526645` (26 Nov 2026, “fix(ci,dudect): fix TruffleHog/liboqs/maturin CI steps and cache-symmetric DudeCT cropping”)  
**Earlier baselines:** `c01ade9f4aaadd9fa736d3d10062d46ac531f0c4` (26 Nov 2026, CI/requirements repairs), `0202b014245ab0d9a4874a82d60e210668fbad01` (26 Nov 2026, security hardening), and `83477fca19909cb52ccaa62a8e630cecb317cfb9` (20 Nov 2026)  
**Audit type:** Source-assisted forensic review with targeted tests; not an accredited laboratory evaluation, not a penetration test, and not a certification.  
**Classification of this report:** Internal engineering/assurance assessment. It contains no production secrets.

---

## 0. Evidence Standard and Limitations

This audit distinguishes five evidence classes:

| Class | Meaning in this report |
|---|---|
| **Demonstrated** | Reproduced locally with a probe or command; result recorded below. |
| **Static defect** | Established by source inspection; not necessarily executed end-to-end. |
| **Design risk** | A property of the architecture or operating model that requires deployment-specific analysis. |
| **Documentation defect** | A claim that is contradicted by code, configuration, or measured host state. |
| **Unknown / not assessed** | Not enough evidence to conclude; explicitly flagged rather than guessed. |

The project’s own `AUDIT_REPORT_ST2027.md`, `REVIEW_REPORT.md`, README scorecards, and “100/100” tables were treated as **claims to verify**, not as evidence. The same applies to in-repo self-tests: passing self-tests show that the code agrees with the tests, not that the security properties hold against an adversary.

Important limits:

- No line-by-line review of every Python or Rust module. Coverage is listed in Section B.
- No reverse engineering or independent validation of `oqs.dll`, `libsodium.dll`, or compiled `.pyd` binaries. Hashes/signatures were observed where the code exposes them; they were not independently verified against an external build.
- No physical TPM, HSM, smartcard, YubiKey, Thales Luna, or Nitrokey was available. Hardware-readiness results reflect the audit host only.
- No external FIPS 140-3 CMVP, Common Criteria, SLSA, ProVerif, or military accreditation evidence was independently validated.
- `pip-audit` and `cargo-audit` were not available locally. `scripts/audit_pins.py` was inspected and exercised, including a simulated OSV outage.
- The full non-live pytest suite was run twice. A default-feature build produced **6 failed, 1955 passed, 30 skipped, 26 deselected**; five failures were traced to the missing `--features lab-surfaces` build flag and one was a startup-race flake. A second run with the CI-equivalent binary was **fully green: 1961 passed, 30 skipped, 26 deselected, exit 0** (Appendix A.2).
- The working tree became clean during the audit: the four source/CI edits observed mid-audit were committed as `d21c280`; only untracked `cache/` remains. See Section B.4.
- The committed baseline moved three times during the audit (`83477fc` → `0202b01` → `c01ade9` → `d21c280`). Findings are stated against `d21c280`; the later commits changed CI/tooling only, not the cryptographic paths. Pre-`0202b01` defects that were fixed are reported separately as remediated, not as open findings.

---

## A. Executive Verdict

**Destroyer-ST2027 is a serious engineering prototype with a materially stronger Rust data plane than its Python lab surface, but it is not ready for ordinary sensitive production, and it is not eligible for military/classified use.**

The strongest parts are real:

- The native Rust path implements a hybrid P-384 + ML-KEM-1024 key exchange, mutual ML-DSA-87 authentication, SHA-384 transcript binding, mandatory peer pinning, PSK defense-in-depth, AES-256-GCM, an RFC 6479-style replay window, memory locking/zeroization, and TPM NVRAM anti-rollback.
- The Rust library tests pass locally (267/267), `cargo clippy --all-targets -- -D warnings` passes, and the selected CI-equivalent Python tests pass (161 passed, 5 skipped).
- The repository contains explicit non-accreditation disclosures (`README.md:36`, `SECURITY.md:7-10`) and a functioning production-gate concept.
- Bandit found 0 medium/high findings at the audited baseline (3,774 low findings remain untriaged).
- The CI workflow blocks on the full non-live pytest suite when built as configured; a CI-equivalent local rerun was fully green (1961 passed, 30 skipped), while a default-feature build produced 6 failures traced to a build mismatch and one flake, not to a KEX regression.

The decision-critical weaknesses are also real:

1. **Production key custody is not enforced.** The documented “zero-disk” production tactical path writes ML-DSA-87 signing seeds to disk and passes `--auth-sk-file` to the Rust binary. The Rust loader accepts it in production without a hardware check. `README.md:920` says `--auth-sk-file` is eliminated in production; the code says otherwise.
2. **The Rust `node` command has a mutual-authentication bypass.** Supplying `--key-file` (or `--key-stdin`) skips key exchange and forwards to `cmd_channel`/`cmd_terminal`, neither of which consults `--require-mutual-auth` or the production posture. This contradicts the claim that classical-only or PSK-only operation is structurally unrepresentable.
3. **The Python AES-GCM IV construction is not durable or key-bound.** It uses a 4-byte per-process random prefix plus a 64-bit counter starting at zero. Fork reseeding was added, but cross-restart and VM-clone nonce reuse remains possible for persistent keys. GCM nonce reuse is catastrophic.
4. **TPM remote attestation can be satisfied with synthetic PCRs and a self-signed quote.** A probe under `P2P_PRODUCTION=1` produced `DEGRADED_SECONDARY_SIMULATION` PCRs, signed them with a freshly generated Ed25519 key, and `verify_attestation` returned `True`. There is no endorsement-key/AK trust anchor, and `hardware_mode` is not checked during verification.
5. **Trust bootstrap is not production-grade.** The tactical auto-provisioner generates both “alpha” and “bravo” identities on the same host, so the “pinned peer key” is not a cross-host trust anchor; the generated root CA is not used by the native path. The repository PKI is self-generated/self-signed, not externally anchored.
6. **Assurance documentation overclaims.** `README.md:1469-1478` scores the project “100/100” across audit-maturity dimensions, including “zero divergence” between cited FIPS algorithms and runtime paths. The repo’s own `AUDIT_REPORT_ST2027.md` simultaneously says “software remediation complete” and lists critical F-01/F-02 algorithm-mismatch findings. The hardware section claims native testing against YubiKey 5 FIPS, Thales Luna, and Nitrokey; the audit host reports 2/7 hardware readiness, no HSM, no FIPS provider, and software PQC.

**No Critical code-level remote-code-execution or unauthenticated key-recovery vulnerability was demonstrated.** The highest technical findings are High severity, and three of them have local/deployment preconditions. That is still incompatible with the project’s high-assurance/military framing.

**Overall score: 60/100** (engineering prototype; conditional for development and controlled evaluation; no-go for sensitive production and military use). The rubric is in Section I.

---

## B. Project Coverage

### B.1 Scale and composition

Counts changed during the audit because builds and test runs generated artifacts. The following are the figures measured at the cutoff:

| Scope | Files | Size | Notes |
|---|---:|---:|---|
| Full filesystem (including `.git`, build output, caches) | 47,220 | 15.03 GB | 24,084 `.o`, 4,278 `.pyc`, 1,306 `.bin`, 1,108 `.rmeta`, 528 `.rlib`, 242 `.exe` |
| Working tree excluding common build/cache directories | 3,598 | 0.42 GB | 848 `.py`, 62 `.rs`, 588 `.json`, 211 `.md` |
| Git-tracked files | 936 | 0.02 GB | 518 `.py`, 62 `.rs`, 54 `.json` |
| Root-level Python application modules | 154 | — | `python -m py_compile` run on all 154; 0 failures |

The earlier “28,780 files / 11.07 GB” figure was a mid-audit snapshot; the tree grew during builds. The audit used the source tree, not the build artifacts, for code review.

### B.2 Inspected in depth (or targeted-scanned)

The following files were read directly or searched at function/line granularity. This is not an exhaustive list of every search, but it covers the evidence cited in this report.

**Python control/lab plane (24):** `secure_p2p.py`, `hybrid_kex.py`, `hybrid_kex_legacy.py`, `cnsa_crypto_gateway.py`, `platform_hsm_interface.py`, `secure_transmit_2027.py`, `production_gate.py`, `secure_key_manager.py`, `cjadc2_cross_domain_guard.py`, `nc3_nuclear_command.py`, `nc3_threshold_mpc.py`, `libsodium_manager.py`, `pqc_algorithms.py`, `secure_enclave_key_storage.py`, `security_tiers.py`, `supply_chain_security.py`, `threshold_cryptography.py`, `hw_readiness.py`, `destroyer.py`, `trust_anchor.py`, `config.json`, `config_production.json`, `credentials/base_alpha_cert.pem`, `credentials/base_alpha_key.pem`.

**Rust data plane (10):** `main.rs`, `kex_auth.rs`, `handshake.rs`, `aead.rs`, `replay.rs`, `keystore.rs`, `auth.rs`, `tpm_nv.rs`, `hardware_enclave.rs`, `Cargo.toml`.

**PKI, CI, supply chain, tests:** `certs/pki_manifest.json`, `certs/sovereign_root_ca.json`, `certs/sovereign_sub_ca.json`, `certs/node_alpha.json`, `certs/node_bravo.json`, `certs/crl.json`, `certs/key_ceremony_affidavit.json`, `.github/workflows/defense_ci.yml`, `scripts/audit_pins.py`, `compliance_reports/cve_scan_offline.json`, `requirements.txt`, `requirements-test.txt`, `README.md`, `SECURITY.md`, `AUDIT_REPORT_ST2027.md`, `REVIEW_REPORT.md`, and the selected tests listed in Appendix A.

Approximate coverage: **~50 files read or function-scanned in depth; ~30 additional files pattern-searched.** Against 848 working-tree Python files and 62 Rust files, this is a partial audit, concentrated on the cryptographic/control paths.

### B.3 Not inspected

- Roughly 800 Python modules, including the NC3 command pipeline, web console, MLS/zero-trust engine, audit ledger, FEC/diode code, key ceremony tooling, and most test modules. Findings in those areas would be additional, not excluded.
- Most Rust modules beyond the KEX/AEAD/keystore/auth/replay/TPM core: `net.rs`, `pacing.rs`, `ratchet.rs`, `pipeline.rs`, `zero_trust.rs`, `x509.rs`, `nc3_mpc.rs`, `fec.rs`, and their integration tests.
- Full Rust workspace tests, integration tests, fuzz targets, `dudect` timing tests, Kani harnesses, and ProVerif models. The CI workflow claims these; this audit did not execute them.
- `ts_rt` and `seL4` test suites.
- Binary reverse engineering of `oqs.dll`, `libsodium.dll`, and compiled Python extensions.
- Physical hardware: TPM operations, PKCS#11 HSM, smartcards, YubiKey, Luna, Nitrokey, secure boot, VBS/HVCI.
- External accreditation evidence: FIPS 140-3 CMVP certificate, Common Criteria/NDcPP evaluation, SLSA attestation verification, ATO.

### B.4 Baseline changes and working-tree state

The committed baseline moved during the audit:

- `83477fc` (20 Nov) → `0202b01` (26 Nov, security/CI hardening) → `c01ade9` (26 Nov, CI/requirements/deny fixes) → `d21c280` (26 Nov, CI and DudeCT/formal-verification tooling fixes).
- `0202b01` fixed the `destroyer.py` syntax error, cleared the 15 Bandit medium findings, fixed the failing production-gate parser test, added fork-safe GCM IV reseeding, added hardware-readiness gating (`P2P_REQUIRE_HARDWARE`/`P2P_HARDWARE_STRICT`), added `--peer-subject` pinning to the Rust PKI KEX, and hardened document-path handling. These are reported as **verified remediations**, not open defects.
- `c01ade9` and `d21c280` changed only CI, requirements, deny config, test paths, and DudeCT/formal-verification tooling relative to `0202b01`; they did not change the cryptographic code cited in this report. In particular, the full Python suite is a **blocking** gate at `.github/workflows/defense_ci.yml:438-442` in both commits; the `|| true` step at `:445-449` runs only `if: failure()` to print an advisory traceback summary. CI also builds the binary with `--features lab-surfaces` at `:436`.

At the final check, `git status --short` showed only `?? cache/`: the four source/CI files previously observed as modified were committed as `d21c280`. No source file was modified in the working tree, so the evidence is reproducible from the committed baseline.

---

## C. Architecture and Trust Boundaries

### C.1 Actual execution paths

```
Operator / CLI
   |
   +-- secure_p2p.py chat|demo|web|monolith --lab
   |      -> Python SecureP2PChat / legacy hybrid KEX (X25519 + Ed25519 + ML-KEM-1024 + ML-DSA-87/SLH-DSA)
   |      -> [LAB ONLY] refused without --lab
   |
   +-- secure_p2p.py node|alpha|bravo (non-lab)
   |      -> production_gate.arm_production_gate()
   |      -> native secure-transmit node --psk-file ... --auth-sk-file/--auth-tpm-sealed ... --peer-auth-pk-file ...
   |      -> Rust: negotiate_ephemeral_kex (P-384 + ML-KEM-1024), mutual ML-DSA-87, AES-256-GCM, replay/state
   |
   +-- secure-transmit node|channel|terminal (direct CLI)
   |      -> if --key-file/--key-stdin: SKIP KEX and mutual auth; load 32-byte symmetric key
   |      -> else if --psk-file: KEX
   |
   +-- secure_transmit_2027.py (Python transport, outer TLS 1.3 + inner Noise XXhfs)
   |      -> outer TLS with mutual cert auth; hostname check off by default
   |      -> inner P-384 + ML-KEM-1024 + ML-DSA-87; PKI if production, else TOFU pin
   |
   +-- platform_hsm_interface.py / trust_anchor.py / certs/
          -> PKCS#11/CNG/TPM or software fallback
          -> self-generated PKI and TPM attestation
```

### C.2 Trust boundaries

| Boundary | What is trusted | What is actually enforced | Residual concern |
|---|---|---|---|
| Operator/CLI | Local operator is trusted | Rust rejects inline secrets (`--key`, `--psk`, PINs) in production; file/stdin paths allowed | `--key-file` bypasses KEX; `--auth-sk-file` bypasses hardware custody |
| Local disk | Key files are 0600/DACL-hardened | `keystore.rs` enforces 0600/share-NONE; `auth-keygen` uses hardened write | Production tactical path deliberately stores long-term ML-DSA-87 seeds on disk |
| Network | Dolev–Yao adversary | Hybrid KEX + mutual ML-DSA-87 + PSK + transcript binding + replay window | Custom protocol; no independent proof; Python path has TOFU/hostname defaults |
| Hardware root | TPM/HSM provides custody/attestation | Optional TPM sealed keys; TPM NV anti-rollback in Rust | HSM not enforced; TPM attestation in Python is synthetic/self-signed |
| PKI/CA | External root or pinned peer keys | Rust pins peer keys/subjects; Python `trust_anchor` can require certs | Repository PKI is self-generated/self-signed; tactical peer pin is locally generated |
| Lab/production | Production gate is sticky/fail-closed | `production_gate.py` latches; `--lab` stripped in release builds | Lab code remains in tree; docs and legacy paths blur the line |
| Supply chain | CI gates, pinned deps, signed binaries | Bandit, clippy, cargo-deny, blocking full suite, OSV pin audit, cosign | No cargo-audit/pip-audit; OSV fallback fail-open; one flaky test |

### C.3 What the design gets right

- The Rust data plane is a genuine separation from Python byte-object memory. The control-plane boundary rationale in `production_gate.py:207-220` is sound.
- `kex_auth.rs` binds the transcript with SHA-384 and uses mutual ML-DSA-87; peer pinning is mandatory outside lab/PKI paths.
- `aead.rs` uses AES-256-GCM; `replay.rs` implements a windowed anti-replay check; `keystore.rs` enforces file permissions and no-symlink reads.
- `tpm_nv.rs` requires a real TPM NVRAM index in production and prohibits emulation; this is a meaningful anti-rollback control.
- The project explicitly disclaims accreditation in `SECURITY.md` and README:36. That honesty is a strength and should be preserved.

---

## D. Critical Findings

**No Critical (CVSS-style ≥9.0) remotely exploitable code-execution or key-recovery vulnerability was demonstrated.** The most serious issues are High-severity assurance/control failures, several with local or deployment preconditions. For a military/classified decision, these are still disqualifying.

| ID | Finding | Severity | Why it is decision-critical |
|---|---|---|---|
| D-1 | Production tactical path uses on-disk ML-DSA-87 seeds; “zero-disk” claim false (F-01) | High | Long-term identity theft → impersonation; hardware custody not enforced |
| D-2 | `secure-transmit node --key-file` bypasses KEX and mutual auth (F-02) | High | Defeats the claimed structural impossibility of PSK/classical-only operation |
| D-3 | GCM IV construction is process-local, not durable/key-bound (F-03) | High | GCM nonce reuse can destroy confidentiality and integrity |
| D-4 | TPM attestation accepts synthetic PCRs and self-signed quotes (F-04) | High (feature) / Medium (current Rust path) | A peer can claim a hardware root of trust it does not have |
| D-5 | Trust bootstrap and PKI are self-generated; tactical peer pin is local (F-05/F-10) | Medium | Mutual auth can be a same-host demo rather than a cross-host trust anchor |

The documentation overclaims (F-09) are not a code vulnerability, but they are **decision-critical**: an accreditor relying on `README.md:1469-1478` would conclude the opposite of what the code and host state show.

---

## E. Complete Finding Register

### E.1 Summary

| ID | Title | Severity | Confidence | Type | Status at `d21c280` |
|---|---|---|---|---|---|
| F-01 | Production tactical path uses on-disk ML-DSA-87 seeds | High | High | Control failure / docs contradiction | Open |
| F-02 | `node --key-file` bypasses KEX and mutual auth | High | High | Policy/design bypass | Open |
| F-03 | GCM IV not durable/key-bound; cross-restart reuse | High | High (defect), Medium (exploit) | Static crypto defect | Open (fork reseed partial) |
| F-04 | TPM attestation accepts synthetic PCRs/self-signed quote | High (feature) / Medium (prod path) | High | Demonstrated control bypass | Open |
| F-05 | Tactical auto-provisioning generates both peer identities locally | Medium | High | Trust bootstrap defect | Open |
| F-06 | Python lab path algorithm mismatch; `FALCON` alias | Medium | High | Documentation/claim mismatch | Open |
| F-07 | Pin audit fails open on OSV outage; offline mirror incomplete | Medium | High | Supply-chain assurance defect | Open |
| F-08 | Dependency advisory coverage gaps; full-suite build reproducibility trap | Low | High | CI/assurance gap | Open |
| F-09 | Hardware/FIPS/100-100 claims exceed evidence | Medium | High (host), Medium (broad) | Assurance/documentation | Open |
| F-10 | PKI self-generated/self-signed, not externally anchored | Medium | High (artifacts), Medium (exploit) | Trust/PKI design | Open |
| F-11 | Outer TLS hostname off by default; TOFU outside production | Medium (non-prod) / Low (armed prod) | High (defaults), Medium (exploit) | Defense-in-depth/design | Open |
| F-12 | `destroyer.py --help` force-arms production gate | Low | High | Operational surprise | Open |
| F-13 | `audit_pins.py` imports `os` only under `__main__` | Low | High | Tooling bug | Open |
| F-14 | Working tree differs from HEAD | Info | High | Baseline ambiguity | Open |
| F-15 | 3,774 Bandit low findings untriaged | Info | High | Hygiene backlog | Open |

### E.2 Detailed findings

---

#### F-01 — Production tactical path uses on-disk ML-DSA-87 seeds; “zero-disk” claim false

**Severity:** High. **Confidence:** High. **Type:** Control failure / documentation contradiction.

**Locations:**
- `secure_p2p.py:16878-16919` (`_auto_provision_tactical_credentials`)
- `secure_p2p.py:16924-16967` (`run_tactical_station`)
- `rust_data_plane/src/main.rs:221-265` (`load_auth_signing_key_from_args`)
- `README.md:920` (“`--auth-sk-file` eliminated in production”)
- `config.json:44-52` (`hsm_required: true`, empty `hsm_library_path`/`hsm_pin`)

**Evidence.** `run_tactical_station` arms the production gate when `lab=False` (`16924-16926`). It then calls `_auto_provision_tactical_credentials()`, which generates `alpha.auth.sk` and `bravo.auth.sk` with the native `auth-keygen` command (`16897-16899`) and stores them under `%LOCALAPPDATA%\ST2027\keys` (or XDG data home) (`16862-16875`). The production native command explicitly includes:

```text
--psk-file tactical_station.psk
--auth-sk-file alpha.auth.sk | bravo.auth.sk
--peer-auth-pk-file bravo.auth.pk | alpha.auth.pk
--require-mutual-auth
```
(`secure_p2p.py:16956-16966`)

The Rust loader accepts `--auth-sk-file` without checking `P2P_PRODUCTION`, `P2P_REQUIRE_HARDWARE_IDENTITY`, or an HSM handle (`main.rs:221-265`). `auth-keygen` writes the seed with the hardened `keystore::write_key_file_truncate` (0600/share-NONE), but that is still disk custody of a long-term signing key.

The README’s claim is therefore false for the documented zero-flag production station. The same is true for `secure_p2p.py node` if the operator supplies `--auth-sk-file`; the code accepts it and the native child accepts it.

**Prerequisites.** Local read access to the key directory, a stolen backup, or an operator who uses `--auth-sk-file`. The attack does not require network access.

**Impact.** Theft of the ML-DSA-87 seed allows impersonation of the station to peers that pin its public key, and permits signing of arbitrary C2 messages. It also defeats the project’s hardware-custody/“zero-disk” assurance claim, which is a core part of its military positioning.

**Safe reproduction.** Source inspection is sufficient. Do not run the tactical station with production credentials. A safe check is to run `secure_p2p.py alpha --help` and inspect the production launch path; optionally run with a temporary key directory and `--lab` to observe the command construction.

**Remediation.** In production, reject `--auth-sk-file` and require either `--auth-tpm-sealed` (PCR-bound) or a PKCS#11 key handle; make `run_tactical_station` provision/use hardware custody and fail closed when it is unavailable; update `README.md:920` and the scorecard; add a startup assertion that no long-term signing seed exists on disk in production.

**Regression test.** A production-posture launch with `--auth-sk-file` must exit nonzero; a launch without a hardware handle must fail; an HSM/TPM handle path must pass; a test must assert that no `.sk` seed is written under the production key directory.

**Status.** Open at `d21c280`. Not remediated by `0202b01` or the later CI commits.

---

#### F-02 — `secure-transmit node --key-file` bypasses KEX and mutual authentication

**Severity:** High as an assurance/control failure; Medium if the local operator is fully trusted and outside the threat model. **Confidence:** High. **Type:** Policy/design bypass.

**Locations:**
- `rust_data_plane/src/main.rs:3439-3490` (`cmd_node`)
- `rust_data_plane/src/main.rs:3474-3482` (bypass condition)
- `rust_data_plane/src/main.rs:1966-1970` (`cmd_channel` loads key)
- `rust_data_plane/src/main.rs:2867-2882` (`cmd_terminal` loads key)
- `rust_data_plane/src/main.rs:283-304` (`mutual_auth_required`, only used by KEX)
- `README.md:24` (“classical-only operation structurally unrepresentable”)

**Evidence.** `cmd_node` only negotiates a KEX when neither `--key-file` nor `--key-stdin` is present and `--psk-file` is present:

```rust
if get_flag(&forwarded, "--key-file").is_none() && !has_flag(&forwarded, "--key-stdin") {
    if get_flag(&forwarded, "--psk-file").is_some() {
        let temp_key = negotiate_ephemeral_kex(&forwarded, &role);
        ...
    } else {
        fail("missing --key-file PATH (or --psk-file PATH) ...");
    }
}
```

If `--key-file` is supplied, the branch is skipped and the command is forwarded to `cmd_channel` or `cmd_terminal`, both of which call `load_key_material` and proceed with the symmetric key. Neither function calls `mutual_auth_required`; a grep shows it is referenced only at lines 3515 and 3785 (KEX listen/connect). There is no production rejection of `--key-file`; the help text advertises it as a normal option (`main.rs:3450`).

**Prerequisites.** Local CLI access plus a 32-byte key file, or a deployment script that uses `--key-file`. The key must be shared with the peer.

**Impact.** A node can run without P-384/ML-KEM-1024 KEX, without ML-DSA-87 mutual authentication, and without transcript binding. This is precisely the “PSK-only/classical-only” mode the README says is structurally impossible. It also means an operator can silently downgrade a production deployment to a symmetric-key channel.

**Safe reproduction.** Static inspection is sufficient. For a non-production check, generate a throwaway 32-byte key in a temp directory and run `secure-transmit node --role initiator --bind 127.0.0.1:0 --to 127.0.0.1:1 --key-file <temp>`; it will proceed to the channel/terminal path without KEX. Do not connect to a real peer.

**Remediation.** Reject `--key-file`/`--key-stdin` in production unless an explicit lab feature is compiled and `--lab` is set; require `--psk-file` plus a hardware-backed ML-DSA-87 identity and a pinned peer key for `node`; call the mutual-auth policy check in `cmd_channel`/`cmd_terminal`, not only in KEX commands; add a negative test for `--require-mutual-auth` with a raw key.

**Regression test.** `P2P_PRODUCTION=1 secure-transmit node --key-file ...` must fail; `cmd_channel` with `--require-mutual-auth` and no auth material must fail; a node with PSK+auth+pin must pass.

**Status.** Open at `d21c280`.

---

#### F-03 — Deterministic GCM IV is process-local, not durable or key-bound

**Severity:** High (cryptographic failure mode); exploitability Medium. **Confidence:** High in the defect, Medium in practical exploitability. **Type:** Static crypto defect / design risk.

**Locations:**
- `cnsa_crypto_gateway.py:53-92` (`_iv_fixed_prefix`, `_iv_counter`, `generate_deterministic_gcm_iv`)
- `platform_hsm_interface.py:23-47` (duplicate implementation)
- `cjadc2_cross_domain_guard.py:261-266` (compartment key reuse)
- Additional call sites: `nc3_nuclear_command.py:1077/1188/1751/1973`, `nc3_threshold_mpc.py:267`, `libsodium_manager.py:33`, `pqc_algorithms.py:6493/6693`, `secure_enclave_key_storage.py:1263/1525`, `secure_key_manager.py:2694`, `secure_p2p.py:16747`, `security_tiers.py:1112`, `supply_chain_security.py:1854`, `threshold_cryptography.py:949`, `platform_hsm_interface.py:80/4676`.

**Evidence.** The IV is `4-byte random prefix || 8-byte big-endian counter`. The counter starts at 1 for each process; the prefix is generated with `secrets.token_bytes(4)` at import. `os.register_at_fork` reseeds the child (`53-73`), which fixes the fork case, but the construction is still:

- not persisted across restarts;
- not bound to a key identifier;
- not coordinated across processes or hosts;
- only 32 bits of per-process separation.

The docstring was narrowed to “no two invocations in this process (or forked children)” (`82-83`), which is accurate, but the surrounding assurance material and the NIST SP 800-38D framing still imply a stronger property. `cjadc2_cross_domain_guard.py` derives a compartment key deterministically from a master secret (`261`) and then uses this IV, so the same key can recur across sessions/restarts.

**Prerequisites.** A persistent key used across process restarts or VM clones, plus either a 32-bit prefix collision (birthday probability becomes material at ~2^16–2^17 process instances) or duplicated RNG state from a VM snapshot. The counter must also overlap, which it does at process start.

**Impact.** GCM nonce reuse under the same key leaks the XOR of plaintexts and can enable authentication-key recovery. For C2/NC3 traffic, this is a confidentiality and integrity failure, not a theoretical nicety.

**Safe reproduction.** Static. A non-destructive demonstration can monkeypatch `secrets.token_bytes` to return a fixed prefix in two subprocesses and show identical first IVs for the same key. Do not use real keys or data.

**Remediation.** Use a persistent per-key nonce state anchored in TPM/HSM, or a random 96-bit nonce with a strictly bounded number of encryptions per key and collision-resistant key lifetime; bind the IV/prefix to a key ID; replace the duplicate implementation with one audited module; add a cross-process/restart uniqueness test; document the key-usage limit.

**Regression test.** Two processes with the same key must never emit the same IV; a simulated restart/VM clone must either reseed from a durable source or fail closed; counter exhaustion must force rekey.

**Status.** Open, with partial mitigation (fork reseed) added at `0202b01`.

---

#### F-04 — TPM attestation accepts synthetic PCRs and self-signed quotes

**Severity:** High for the attestation feature; Medium for the current Rust production path because the Rust path does not consume this Python attestation. **Confidence:** High (demonstrated). **Type:** Demonstrated control bypass.

**Locations:**
- `platform_hsm_interface.py:6603-6682` (`_read_pcr_values`; synthetic PCR fallback)
- `platform_hsm_interface.py:6700-6786` (`generate_attestation`; `hardware_mode`)
- `platform_hsm_interface.py:6787-7060` (`verify_attestation`)
- `secure_p2p.py:4886-4956` (legacy/lab chat uses `get_tpm_attestation` and verifies with the peer identity key)

**Evidence.** With `P2P_PRODUCTION=1` and native TPM access gated off, `_read_pcr_values` synthesizes PCR 0/1/2/7 deterministically from a hardware ID and labels the attestation `DEGRADED_SECONDARY_SIMULATION`. `verify_attestation` checks the timestamp, nonce, PCR hash/quote, and PCR 7 nonzero, then verifies the signature against a caller-supplied `public_key`. It never checks `hardware_mode`, and there is no endorsement-key/AK certificate chain.

The audit probe did the following (no real TPM):

```python
os.environ["P2P_PRODUCTION"] = "1"
# unset P2P_ALLOW_TPM_NATIVE and other overrides
sk = ed25519.Ed25519PrivateKey.generate()
t = TPMRemoteAttestation()
att = t.generate_attestation(signer_callback=lambda d: sk.sign(d))
assert att["hardware_mode"] == "DEGRADED_SECONDARY_SIMULATION"
assert t.verify_attestation(att, public_key=sk.public_key(), expected_nonce=t.nonce) is True
```

Observed log lines included “TPM native access gated off … software-synthesized attestation only,” “PCR values synthesized via platform deterministic derivation,” and “TPM remote attestation verified successfully.” In other words, the verifier accepted a quote that the same process had just fabricated and signed with a non-TPM key.

**Prerequisites.** The legacy/lab path or direct use of `TPMRemoteAttestation`; native TPM access not enabled; the attacker can sign with its own identity key. In the current Rust production path, this specific class is not used, so the impact is primarily on the Python attestation feature and the claim that hardware state is verified.

**Impact.** A malicious peer can claim Secure Boot/PCR values it does not have. The attestation does not prove a TPM produced the quote; it proves only that the peer signed the values. This defeats the stated “remote hardware attestation” control.

**Safe reproduction.** The probe above is safe and does not touch a TPM. It should be turned into a regression test that expects rejection.

**Remediation.** Verify the quote against a TPM endorsement key / AK certificate chain and a pinned manufacturer root; reject `DEGRADED_SECONDARY_SIMULATION` in production; bind PCR policy and nonce to the session transcript; require `hardware_mode` to be a hardware value; do not accept a caller-supplied arbitrary public key as the root of trust.

**Regression test.** A synthetic/self-signed attestation must be rejected in production; an attestation signed by a non-EK key must fail; a valid EK/AK chain must pass.

**Status.** Open. The Rust production path has TPM PCR-sealed key unsealing, which is a different and stronger mechanism, but it does not fix this Python attestation code.

---

#### F-05 — Tactical auto-provisioning generates both peer identities locally

**Severity:** Medium. **Confidence:** High. **Type:** Trust bootstrap defect.

**Locations:** `secure_p2p.py:16878-16919`, `16945-16967`.

**Evidence.** `_auto_provision_tactical_credentials()` generates both `alpha.auth.sk/pk` and `bravo.auth.sk/pk` on every host (`16897-16899`), then creates a local `military_root_ca.crt` and node certs (`16905-16917`). `run_tactical_station` uses the local `peer_pk` file as `--peer-auth-pk-file` (`16946`, `16963`). The generated root CA is not passed to the native command at all (`16956-16966`); the native path uses PSK + auth key + peer pin only. CA creation failure is swallowed by `except Exception: pass` (`16918-16919`).

**Prerequisites.** Use of the zero-flag `alpha`/`bravo` production station.

**Impact.** On two independent hosts, the locally generated “peer” public key will not match the remote station’s real key, so mutual auth fails. If operators copy key files to make it work, the pin is no longer an independent trust anchor; it is a shared local fixture. The “zero manual flags” production mode is therefore a same-host demo or a manual key-distribution exercise, not a production trust bootstrap. The unused CA adds a false impression of PKI.

**Safe reproduction.** Source inspection; a two-host test with default provisioning will show a pin mismatch (not run here because it requires two hosts and network).

**Remediation.** Provision the peer’s public key out-of-band or via an authenticated enrollment protocol; fail closed if the peer key is absent or does not match; use a real external CA/HSM ceremony if PKI is required; remove the silent `except` and surface CA failures.

**Regression test.** A two-host provisioning test must establish mutual auth without copying private keys; a mismatched peer key must fail; a CA failure must fail closed.

**Status.** Open.

---

#### F-06 — Python lab path algorithm mismatch and `FALCON` alias

**Severity:** Medium. **Confidence:** High. **Type:** Documentation/claim mismatch.

**Locations:** `secure_p2p.py:342` (import), `2463` (instantiation), `17161` (`chat` is `[LAB ONLY]`); `hybrid_kex.py:33-45` (re-export); `hybrid_kex_legacy.py:339` (`FALCON = MLDSA_SLHDSA_HybridSignature`); `README.md:24`; `AUDIT_REPORT_ST2027.md:43-44`.

**Evidence.** `secure_p2p.py` imports `HybridKeyExchange` from `hybrid_kex`, which re-exports the legacy class from `hybrid_kex_legacy.py`. The legacy construction uses X25519/Ed25519 + ML-KEM-1024 + ML-DSA-87/SLH-DSA, not P-384. The `FALCON` name is a backward-compatibility alias for the ML-DSA/SLH-DSA hybrid, not Falcon-1024. The `chat` parser is explicitly `[LAB ONLY] Quarantined legacy SecureP2PChat` and requires `--lab` (`17161-17162`). README:24 says “the Python orchestrator uses `SecP384r1MLKEM1024`.”

**Prerequisites.** Use of the lab chat path, or reliance on the README for algorithm claims.

**Impact.** A reader could believe the Python path provides P-384’s ~192-bit classical strength and a P-384 hybrid; the lab path provides X25519’s ~128-bit classical component. The `FALCON` alias can also mislead reviewers into thinking Falcon-1024 is in use. This matters for accreditation evidence and for anyone who treats the lab path as production.

**Safe reproduction.** Inspect the imports/alias; run `secure_p2p.py chat --help` and observe the required `--lab`.

**Remediation.** Correct README:24 to distinguish the Rust production path from the legacy Python lab path; remove or rename the `FALCON` alias; add a docs-truth test that asserts the actual algorithms per path.

**Regression test.** `test_docs_truth_in_claims.py` should fail if the README claims P-384 for the Python chat path; a lab-path test should assert X25519/Ed25519 is confined to `--lab`.

**Status.** Open (documentation); the production Rust path itself is P-384 + ML-KEM-1024.

---

#### F-07 — Pin audit fails open on OSV outage; offline mirror is incomplete

**Severity:** Medium. **Confidence:** High (demonstrated). **Type:** Supply-chain assurance defect.

**Locations:** `scripts/audit_pins.py:65` (`os` import issue), `92-101` (fallback), `compliance_reports/cve_scan_offline.json`.

**Evidence.** In the exception path, if `mirror_file.exists()`, the script prints a warning and sets `data = {"vulns": []}` **without parsing the mirror**. A probe with a mirror containing `CVE-TEST-0001` for `demo-package==1.2.3` and a simulated OSV outage produced:

```text
WARN demo-package==1.2.3: OSV unreachable (simulated OSV outage), consulting verified offline mirror
OK   demo-package==1.2.3: no known vulns
All pinned packages clean - PASS
```

The `--offline` path does parse the mirror and correctly failed the same fixture, so the defect is specifically the online-with-mirror fallback. Separately, the shipped `compliance_reports/cve_scan_offline.json` contains only 4 entries (cryptography, psutil, pycryptodome, pyyaml), each marked `skipped_offline: true` with `osv_ids: []`, while `parse_pins()` returns 29 pins. `audit_pins.py --offline` reports all 29 as “no known vulns” because packages absent from the mirror are treated as clean. The artifact is not a complete vulnerability mirror and has no freshness/signature metadata.

The script also references `os.environ` at line 65 but imports `os` only inside `if __name__ == "__main__"` (line 128); importing the module and calling `main()` programmatically raises `NameError`. Script execution happens to work because `os` is imported before `main()`.

**Prerequisites.** OSV outage or air-gapped/offline operation; a mirror that is incomplete or stale.

**Impact.** Vulnerable pins can pass CI or an air-gapped audit. The artifact can be mistaken for evidence of a clean scan when it is not a vulnerability database at all.

**Safe reproduction.** The probe described above; it uses a synthetic package and CVE, no network or real dependencies. The offline 29-pin run is also safe.

**Remediation.** In the fallback, parse the mirror and fail if the package/version is absent or the mirror is stale; require a signed, timestamped mirror with full pin coverage; add `pip-audit` and `cargo-audit` to CI; import `os` at module scope; add tests for outage, missing package, stale mirror, and malformed mirror.

**Regression test.** A mirror containing a vulnerability must fail even when OSV is unreachable; an absent package must fail closed; a stale or unsigned mirror must fail; importing the module must not raise.

**Status.** Open.

---

#### F-08 — Dependency advisory coverage has gaps; full-suite reproducibility needs work

**Severity:** Low. **Confidence:** High. **Type:** CI/assurance gap.

**Locations:** `.github/workflows/defense_ci.yml:436`, `:438-449` (HEAD `d21c280`), `scripts/audit_pins.py`, `compliance_reports/cve_scan_offline.json`.

**Evidence.** The workflow at `d21c280` **blocks** on the full non-live pytest suite (`:438-442`) as well as on Bandit, `cargo clippy -D warnings`, `cargo-deny`, the data-plane/ts_rt/seL4 steps, ProVerif, cosign, and the OSV pin audit. The separate `|| true` step (`:445-449`) runs only `if: failure()` to print an advisory traceback summary; it does not weaken the blocking gate. There is no `cargo-audit` or `pip-audit`; OSV coverage is limited to pinned direct requirements and has the F-07 fallback weakness.

A local full-suite run with a default-feature binary produced **6 failed, 1955 passed, 30 skipped, 26 deselected** in 1,062 s. Five failures (`tests/test_tactical_operations_suite.py` 01–05) called lab-only commands (`cot-beacon`, `tactical-msg`, `eam-auth`) in a binary built without `--features lab-surfaces`. A second run with the CI-equivalent `--features lab-surfaces` binary was **fully green: 1961 passed, 30 skipped, 26 deselected, exit 0** in 1,185 s; rebuilding with that feature also made all 6 tactical tests pass in isolation. The remaining first-run failure (`test_kex_listen_connect_hybrid_establishment`, `bundle read failed`) passed on isolated rerun, in a manual two-process loopback probe with matching SAS and identical derived keys, and in the second full run. It was a one-off startup race, not a demonstrated KEX defect.

**Prerequisites.** A dependency advisory not covered by the pin audit; a local build that differs from CI; a rare flaky test in the blocking gate.

**Impact.** Transitive/unpinned dependencies and Rust crates may carry advisories that CI never checks. A local run that omits `--features lab-surfaces` produces a misleading six-failure signal. The observed flake did not recur, but a startup race remains possible in the blocking gate. These are assurance/reproducibility issues, not demonstrated code regressions.

**Safe reproduction.** Inspect the workflow and run the full suite locally with and without `--features lab-surfaces`. The isolated KEX rerun and the loopback probe are safe. Do not introduce deliberately failing tests into a shared branch.

**Remediation.** Add `cargo-audit` and `pip-audit`; fix the OSV mirror fallback (F-07); document that local full-suite runs require `--features lab-surfaces`; replace the KEX test’s fixed 1-second sleep with a bind-readiness wait; keep the blocking gate.

**Regression test.** A known-vulnerable pin must fail CI; a local full-suite run built as CI builds must be green; the KEX test must pass repeatedly under load.

**Status.** Open at `d21c280`, downgraded to Low after the CI-equivalent full run passed. **Correction:** the earlier assessment that the full suite was advisory was a misreading of the `if: failure()` rerun step; this section supersedes it.

---

#### F-09 — Hardware, FIPS, and “100/100” claims exceed evidence

**Severity:** Medium. **Confidence:** High for the audit host; Medium for broad deployment claims. **Type:** Assurance/documentation.

**Locations:** `README.md:917-924` (hardware claims), `README.md:1469-1478` (“100/100”), `README.md:1487-1500` (“RESOLVED” matrix), `config.json:44-52`, `AUDIT_REPORT_ST2027.md:12` and `148-155`, `SECURITY.md:7-10`.

**Evidence.** On the audit host, `hw_readiness.collect()` returned `strict_ok=False`, 2/7 HAVE (DMA protection, TPM 2.0 device), and MISSING for Administrator rights, UEFI Secure Boot (disabled), VBS/HVCI (not enforcing), hardware key custody (no PKCS#11/CNG backend; “keys would live in software RAM”), and FIPS 140-3 provider (no loaded provider). `secure_p2p.py selftest` logs “Using software implementation of PQC algorithms.” `config.json` declares `enable_hsm: true`, `hsm_required: true`, `tpm_required: true`, but `hsm_library_path` and `hsm_pin` are empty and `tpm_device` is `/dev/tpm0` (a Linux path) on a Windows host.

The README claims native testing against YubiKey 5 FIPS, Thales Luna PCIe/Network HSM, and Nitrokey HSM “without Python wrappers” (`917`). No in-repo hardware transcript, test log, certificate, or CI job was found to substantiate that claim. The README’s 100/100 scorecard says “zero divergence between cited FIPS 203/204/205 algorithms and runtime code paths” (`1475`), yet the Python lab path uses legacy X25519/Ed25519 and the `FALCON` alias (F-06). The same README marks “P0-06 (CNSA 2.0 P-384 KEX)” as RESOLVED (`1500`), while the Python lab path does not use P-384.

The project’s own `AUDIT_REPORT_ST2027.md` says “SOFTWARE REMEDIATION COMPLETE FOR TESTED CODEPATHS” (`12`) and then lists F-01/F-02 as Critical, saying they “undermine the project’s fundamental security claim” (`148-155`). That is an internal contradiction.

The positive counterweight is that `SECURITY.md:7-10` and README:36 explicitly disclaim third-party accreditation, physical FIPS enclosures, and synthetic test fixtures. That disclosure is accurate and should be preserved; the problem is the later 100/100 and hardware-tested language.

**Prerequisites.** Reliance on the documentation for procurement, accreditation, or deployment decisions.

**Impact.** An evaluator could overestimate hardware validation, FIPS status, and remediation completeness. In a military/classified context, this is a serious assurance risk even if no code vulnerability is exploited.

**Safe reproduction.** Run `hw_readiness.collect()` and inspect `config.json`, README:917-924/1469-1500, and `AUDIT_REPORT_ST2027.md:12,148-155`.

**Remediation.** Replace the 100/100 scorecard with an evidence matrix that states what was tested, on which hardware, with which certificates; remove or qualify “native testing” claims until evidence exists; mark F-06/F-09/F-10 as open in the matrix; add a docs-truth test for hardware/FIPS claims; require CMVP/CC/ATO evidence before using those terms.

**Regression test.** A docs test must fail on “100/100,” “zero divergence,” or “tested against YubiKey/Luna/Nitrokey” without a linked evidence artifact; a CI job must record the hardware inventory.

**Status.** Open.

---

#### F-10 — PKI is self-generated/self-signed and not externally anchored

**Severity:** Medium. **Confidence:** High for the artifacts; Medium for exploitability. **Type:** Trust/PKI design.

**Locations:** `certs/pki_manifest.json`, `certs/sovereign_root_ca.json`, `certs/sovereign_sub_ca.json`, `certs/node_alpha.json`, `certs/node_bravo.json`, `certs/crl.json`, `certs/key_ceremony_affidavit.json`, `credentials/base_alpha_cert.pem`, `trust_anchor.py`.

**Evidence.** `certs/pki_manifest.json` declares `root_authority: CN=Sovereign-Defense-Root-CA`, a `merkle_root`, and SHA3-512 hashes of the JSON artifacts. It is a self-generated/self-hashed manifest; no external root, HSM-backed ceremony transcript, or independent signature verification was found. `credentials/base_alpha_cert.pem` is a self-signed P-384 certificate:

```text
subject: OU=Certificate Authority,O=Secure P2P Chat,CN=P2P-a8275825b34ba691
issuer:  OU=Certificate Authority,O=Secure P2P Chat,CN=P2P-a8275825b34ba691
valid:   2026-09-08 to 2027-09-08
self_signed: True
sig_alg: 1.2.840.10045.4.3.4 (ecdsa-with-SHA384)
```

`credentials/` is gitignored; the certificate and encrypted key are local fixtures. The Rust path pins peer keys/subjects, which is a valid trust model if the pins are provisioned out-of-band; the repository does not demonstrate that provisioning.

**Prerequisites.** PKI mode or reliance on the repository CA; local file write/replace access.

**Impact.** A local attacker who can replace the CA/certs or the pinned peer key can mint identities. The “sovereign root CA” is not externally anchored, so it cannot support an accreditation claim by itself. The tactical path’s peer pin is locally generated (F-05), compounding the issue.

**Safe reproduction.** Inspect the certificate and manifest; verify with `openssl x509`/Python `cryptography`. No private key use is required.

**Remediation.** Use an external root CA or an HSM-backed, witnessed ceremony; sign the manifest with an independently pinned key; publish the root fingerprint out-of-band; require peer keys to be provisioned, not generated locally; add chain-verification tests against the external root.

**Regression test.** Production must reject a self-signed/unanchored root; a manifest with a bad signature must fail; a peer key not provisioned out-of-band must fail.

**Status.** Open (assurance); the self-signed cert is not a vulnerability by itself if pins are correct, but it is not an accreditation-grade PKI.

---

#### F-11 — Outer TLS hostname verification off by default; TOFU outside production

**Severity:** Medium in non-production/default configurations; Low in correctly armed production. **Confidence:** High for defaults; Medium for exploitability. **Type:** Defense-in-depth/design.

**Locations:** `secure_transmit_2027.py:577-609` (`_xxhfs_peer_gates`), `1190-1218` (`check_hostname`), `trust_anchor.py:100-107` (`pki_required`/`ephemeral_required`).

**Evidence.** The outer TLS context loads the CA and sets `CERT_REQUIRED`, but `check_hostname` defaults to `_env_true("P2P_CHECK_HOSTNAME")`, i.e. false unless explicitly enabled. The code documents this as deliberate domain-fronting: the outer SNI is a cover domain, and peer identity is authenticated by the inner Noise/PQ handshake. The inner gate uses PKI when `pki_required()` is true (which includes `P2P_PRODUCTION`), otherwise it falls back to TOFU pinning (`check_pin`).

**Prerequisites.** Non-production/default configuration, or a production deployment that fails to arm the production gate; an attacker with a CA-trusted certificate for the outer connection; first-contact TOFU.

**Impact.** In default/non-production mode, the outer certificate’s hostname is not checked, so any CA-trusted certificate can terminate the outer TLS; the inner pin is the compensating control. If the inner gate is in TOFU mode, first contact is vulnerable to MITM. In correctly armed production, `pki_required()` and the inner cert/pin gate reduce this to a defense-in-depth concern.

**Safe reproduction.** Inspect the defaults; run a test with `P2P_PRODUCTION` unset and a mismatched hostname/cert to observe the warning. Do not use real peers.

**Remediation.** Require an explicit fronting profile for hostname-off operation; enable hostname verification for direct deployments; force PKI in production; add a MITM test with a valid-but-wrong-name certificate.

**Regression test.** Production without PKI must fail; a hostname mismatch in direct mode must fail; TOFU must never be selected when production posture is armed.

**Status.** Open (design/default), mitigated in correctly armed production.

---

#### F-12 — `destroyer.py --help` force-arms the production gate

**Severity:** Low. **Confidence:** High (observed). **Type:** Operational surprise.

**Location:** `destroyer.py:34` (`production_gate.arm_production_gate("destroyer_cli_default")`).

**Evidence.** Running `python destroyer.py --help` exited 0 but logged `production_gate: FORCE-ARMED (destroyer_cli_default)`. A help invocation should not change security posture.

**Prerequisites.** Invoke the CLI with `--help` (or any path that reaches the default arm).

**Impact.** In-process posture changes; scripts that source/import the CLI may be surprised. The process exits after help, so persisted impact is low.

**Safe reproduction.** `python destroyer.py --help` (observed; exit 0).

**Remediation.** Arm production only after argument parsing and only for operational commands; do not arm for `--help`/`--version`.

**Regression test.** `--help` must not log "FORCE-ARMED" and must not set `P2P_PRODUCTION`.

**Status.** Open (low).

---

#### F-13 — `audit_pins.py` imports `os` only under `__main__`

**Severity:** Low. **Confidence:** High. **Type:** Tooling bug.

**Location:** `scripts/audit_pins.py:65`, `127-129`.

**Evidence.** Calling `scripts.audit_pins.main()` programmatically raises `NameError: name 'os' is not defined` at line 65. Running the file as a script works because `import os` executes before `main()` in the `__main__` block.

**Prerequisites.** Import-based use in tests or automation.

**Impact.** Tooling/test fragility; not a security bypass by itself.

**Safe reproduction.** Import the module and call `main()`; observe the `NameError`.

**Remediation.** Move `import os` to module scope.

**Regression test.** Import the module and call `main()` with `--offline`; it must not raise.

**Status.** Open (low).

---

#### F-14 — Baseline moved during the audit (resolved at cutoff)

**Severity:** Info. **Confidence:** High. **Type:** Baseline ambiguity.

**Evidence.** Mid-audit `git status` showed four modified files; they were committed as `d21c280` at 11:11:42. The final `git status --short` showed only `?? cache/`, i.e. no source modification.

**Impact.** Earlier intermediate observations must be attributed to the correct commit. This report uses `d21c280` throughout.

**Remediation.** For an external evaluation, freeze the commit and record the tree hash in the evidence package.

**Status.** Resolved at cutoff; baseline recorded.

---

#### F-15 — Bandit low findings untriaged

**Severity:** Info. **Confidence:** High. **Type:** Hygiene backlog.

**Evidence.** Bandit over the active tree reported 0 high, 0 medium, and 3,774 low findings. The low count is not a clean bill of health; low-severity rules can still indicate real defects (e.g., subprocess use, asserts, broad exceptions).

**Impact.** Unknown residual code-quality/security issues.

**Remediation.** Triage by rule and file; suppress only with justification; track in the backlog.

**Status.** Info.

---

### E.3 Remediated during the audit (not open findings)

These items were confirmed fixed at `0202b01` and remain fixed at `d21c280`; they should be credited:

| Item | Earlier state | Verified state |
|---|---|---|
| `destroyer.py` syntax error | Prevented CLI execution | `python destroyer.py --help` exits 0 |
| Bandit medium findings | 15 medium | 0 medium/high at HEAD |
| Production-gate parser test | Failing | Passes |
| GCM fork reuse | Forked children inherited IV state | `os.register_at_fork` reseeds child (residual F-03 remains) |
| Hardware-readiness gating | No strict gate | `P2P_REQUIRE_HARDWARE`/`P2P_HARDWARE_STRICT` gate added |
| Rust PKI peer pinning | Missing `--peer-subject` | Added production check at `main.rs:3550` |
| Document-path handling | Hardening gap | Hardened |

These remediations show the project responds to findings. They do not close F-01–F-11.

---

## F. Cryptographic and Protocol Assessment

### F.1 Primitive inventory

| Function | Rust production path | Python lab/transport path | Assessment |
|---|---|---|---|
| KEM | ML-KEM-1024 (FIPS 203) + P-384 ECDH | ML-KEM-1024 + X25519 (legacy) or P-384 (Noise XXhfs) | Strong primitives; Python lab path is weaker than README claims |
| Signatures | ML-DSA-87 (FIPS 204), mutual | ML-DSA-87 + SLH-DSA-256f; `FALCON` alias is not Falcon | Strong on paper; alias/documentation mismatch |
| AEAD | AES-256-GCM | AES-256-GCM (CNSA gateway), ChaCha20-Poly1305 (legacy ratchet) | Rust AEAD fine; Python GCM IV management defective (F-03) |
| Hash/KDF | SHA-384, HKDF-SHA384 | SHA-384/SHA3-512, HKDF | Appropriate; no independent KDF proof |
| Replay | RFC 6479-style window + state file | Various app-level checks | Rust control is a strength |
| Randomness | OS/liboqs | OS/liboqs/secrets | No RNG health tests reviewed; IV defect is the main issue |
| Key custody | 0600/DACL keystore; optional TPM PCR seal | PBKDF2/DPAPI envelope; optional PKCS#11/TPM | Hardware not enforced; production disk seeds (F-01) |
| Attestation | TPM NV anti-rollback; no remote quote in Rust | Synthetic PCR quote (F-04) | Python attestation is not hardware-rooted |

### F.2 Key exchange and authentication

The Rust KEX is the strongest part of the system. `kex_auth.rs` and `handshake.rs` implement a P-384 + ML-KEM-1024 exchange, bind the transcript with SHA-384, authenticate both sides with ML-DSA-87, require a PSK as defense-in-depth, and require a pinned peer key outside the lab/PKI path. The `--peer-subject` check added at `main.rs:3550` is a meaningful improvement. This is a coherent hybrid design.

The weaknesses are at the policy edges, not the primitive choices:

- The `--key-file` path bypasses the entire KEX (F-02).
- The production tactical path loads a disk seed instead of a hardware handle (F-01).
- The tactical peer pin is locally generated (F-05).
- The Python lab path uses a different, weaker KEX than the README claims (F-06).
- No independent proof or review of the custom protocol composition was found. The ProVerif gate in CI is a positive, but this audit did not run it or validate model fidelity.

### F.3 AEAD and nonce management

AES-256-GCM is the right choice for CNSA 2.0. The Rust path uses per-frame keys/ratchets and a replay window; the audit did not find a nonce defect in the Rust AEAD code. The Python CNSA gateway’s deterministic IV construction is the clear defect (F-03), and it is duplicated across modules, which increases the chance that one copy is fixed and another is missed.

The project’s own README marks “F-02 (Nonce Uniqueness)” as resolved by directional key separation (`README.md:1488`). Directional keys reduce reflection, but they do not fix a 4-byte prefix/counter that is not durable across restarts. The claim is overbroad.

### F.4 Forward secrecy and post-compromise security

The Rust ephemeral KEX provides session forward secrecy against later static-key compromise, assuming the ephemeral secrets are erased and the KEX is sound. The Rust path also has a `PcsRatchet` (seen at `main.rs:2931`) and epoch rekeying claims in the README. This audit did not verify the PCS construction, its state erasure, or its recovery properties. **Do not claim PCS or full forward secrecy for the production path without an independent review.**

The Python lab path has a Double Ratchet, but it is explicitly lab-only. Its security does not transfer to the Rust path by assertion.

### F.5 Quantum resistance

ML-KEM-1024, ML-DSA-87, and SLH-DSA-256f are standardized post-quantum algorithms. Using them is a reasonable design choice for a 2027 transition system. “Quantum-resistant” is still a claim about a deployed implementation and its key management, not a property that follows from the algorithm names. In particular:

- A quantum attacker who compromises the classical authentication key may still impersonate a peer if the protocol’s authentication is not fully PQ; the Rust path uses ML-DSA-87, which is PQ on paper, but the Python lab path and the self-signed PKI weaken the end-to-end story.
- The system’s security ultimately depends on the hardware root, key custody, and provisioning, which are the areas with the most findings.

### F.6 Side channels and implementation assurance

The repo claims constant-time tests (`dudect`) and Kani harnesses; this audit did not run them. `cargo clippy -D warnings` passing is a code-quality signal, not a side-channel proof. The Python code has many variable-time operations and broad exception paths; it is not a constant-time boundary. The Rust code uses `zeroize`, memory locking, and compiler fences; those are good practices, but they do not prove absence of timing/leakage issues.

### F.7 Formal verification

The CI workflow includes a ProVerif gate and the README claims “ProVerif 2.05 proven TRUE.” This audit did not run ProVerif or inspect the model’s fidelity to the implementation. A symbolic proof of a model that differs from the code is not evidence about the code. The model-to-code gap should be documented and independently reviewed.

### F.8 Cryptographic verdict

**Primitives: strong. Protocol composition: plausible but custom and not independently reviewed. Key management and policy enforcement: not production-grade. Overall: not high-assurance.**

---

## G. Comparative Assessment: Signal, WhatsApp, and ST2027

This comparison is about **assurance and fitness for purpose**, not just algorithm names. Sources reviewed: Signal’s PQXDH specification (revision 3, 2023-05-24, updated 2024-01-23), Signal’s Double Ratchet specification (revision 4, 2025-11-04), and WhatsApp’s public security page. Facts are marked verified/inference/unknown.

| Property | ST2027 | Signal | WhatsApp | Evidence/confidence |
|---|---|---|---|---|
| E2EE design | Custom hybrid KEX + mutual ML-DSA-87 + AEAD; lab path legacy | PQXDH (X25519 + Kyber-family KEM) + Double Ratchet | Signal Protocol per WhatsApp’s public description | Signal specs verified; WhatsApp client internals not independently verified |
| PQ key agreement | ML-KEM-1024 + P-384 (Rust) | PQXDH hybrid | Public PQ status not verified in this audit | Signal spec verified; WhatsApp unknown |
| PQ authentication | ML-DSA-87 mutual (Rust) | PQXDH authentication is explicitly **not** quantum-secure per spec §4.1 | Not verified | Signal spec verified; ST2027 design claim, implementation assurance lower |
| Forward secrecy | Ephemeral KEX; PCS claims not independently verified | Double Ratchet provides FS/PCS per spec | Signal Protocol per public description | Signal spec verified; ST2027 PCS unknown |
| Metadata protection | Constant-rate pacing/chaff claimed; not independently measured | Sealed sender, metadata minimization | Meta metadata exposure; not a anonymity system | Design claims vs deployed evidence |
| Key custody | Optional HSM/TPM; production disk seeds found | OS keystore; no mandatory hardware token | OS keystore; no mandatory hardware token | ST2027 F-01; consumer platforms differ |
| Open specification | In-repo docs/models; custom protocol | Public PQXDH/Double Ratchet specs | Public whitepaper/description; client proprietary | Signal strongest; WhatsApp mixed |
| Independent review | No external audit evidence found | Formal analyses cited by Signal; broad public review | Not verified in this audit | Do not equate popularity with audit |
| Certification | No CMVP/CC/ATO; self-disclosed | No military accreditation claimed | No military accreditation claimed | ST2027’s own disclosure |
| Deployment maturity | Prototype/lab + Rust core | Global consumer deployment | Global consumer deployment | Inference from public docs |

**Interpretation.**

- Signal is the stronger comparison for **protocol transparency and formal analysis**: its PQXDH and Double Ratchet specs are public, and Signal explicitly notes that PQXDH authentication is not quantum-secure. ST2027’s ML-DSA-87 mutual auth is stronger on paper, but its implementation and provisioning are less mature and not independently reviewed.
- WhatsApp is a large deployed messenger using the Signal Protocol, but its client is proprietary and this audit did not verify its current PQ status or backup key management. It is not a model for classified C2.
- ST2027 is aiming at a different problem: fixed military peers, hardware custody, anti-rollback, constant-rate traffic, and an air-gapped/authoritarian threat model. Its declared primitives exceed consumer messengers in some dimensions, but its **evidence** is far below Signal’s and its operational assurance is below both. For military/classified use, none of these consumer messengers is a substitute for an accredited system; ST2027 would need the accreditation and hardware evidence it currently lacks.

**Marked unknowns.** WhatsApp’s current PQ deployment, the exact KEM parameter in Signal’s deployed PQXDH, WhatsApp’s backup key hierarchy, and the independent audit status of both consumer clients were not verified in this audit. Do not use this table as a substitute for those reviews.

---

## H. Engineering Quality

### H.1 Rust data plane

**Strengths:**

- Clear module separation (`kex_auth`, `handshake`, `aead`, `replay`, `keystore`, `auth`, `tpm_nv`).
- Mutual ML-DSA-87, transcript binding, pins, PSK defense-in-depth.
- AES-256-GCM, replay window, state locking.
- 0600/share-NONE key files, no-symlink reads, zeroization, memory locking.
- TPM NV anti-rollback with production emulation prohibition.
- 267/267 library tests pass; `cargo clippy --all-targets -- -D warnings` passes.

**Weaknesses:**

- Policy checks are concentrated in KEX commands; `channel`/`terminal` do not enforce mutual auth.
- `--key-file` is a first-class option that bypasses the security model.
- `--auth-sk-file` is accepted in production; hardware custody is optional.
- The custom protocol has no independent review; PCS claims are not proven.

### H.2 Python control/lab plane

**Strengths:**

- The production gate is sticky and fail-closed; `--lab` is required for legacy surfaces.
- `enforce_control_plane_boundary` correctly identifies the immutable-bytes problem.
- Secure key manager uses PBKDF2-HMAC-SHA512 600k / DPAPI envelope, random salt, and best-effort permissions.
- The code contains extensive negative tests and self-tests.

**Weaknesses:**

- A large monolith (`secure_p2p.py` is 17k+ lines) with lab and production paths in one tree.
- Duplicate crypto implementations (two deterministic-IV modules, multiple KEX paths).
- Synthetic TPM attestation that can be self-signed (F-04).
- Deterministic GCM IV not durable/key-bound (F-03).
- Broad `except Exception: pass` patterns, including CA provisioning failure.
- Algorithm/documentation drift (F-06).

### H.3 CI and supply chain

**Strengths:**

- Blocking full non-live pytest suite (`:438-442`), Bandit, clippy `-D warnings`, cargo-deny, ProVerif, cosign, OSV pin audit, and selected pytest gates.
- CI builds the Rust binary with `--features lab-surfaces` at `:436`, matching the tactical tests’ expectations.
- `cargo-deny` license/advisory policy; cosign signing.
- `scripts/audit_pins.py` performs real OSV queries in the online path and fails closed when the mirror is absent.

**Weaknesses:**

- No `cargo-audit`/`pip-audit`.
- OSV fallback fail-open and incomplete offline mirror (F-07).
- Hardware/FIPS claims not backed by a CI hardware job.
- The full suite is blocking; local runs require the lab-surfaces build, and one KEX startup-race flake was observed once (not reproduced in the CI-equivalent green run).
- The CI file was edited during the audit and committed as `d21c280`; the evaluated workflow is now pinned to that commit.

### H.4 Tests and verification

- 161 selected Python tests passed, 5 skipped; 267 Rust library tests passed; `py_compile` 154/154; selftests 8/8 and `SELFTEST-OK`.
- These are **self-tests**. They demonstrate internal consistency and catch regressions; they do not establish adversarial security.
- Full non-live suite, default-feature binary: 1955 passed, 30 skipped, 6 failed (five lab-surface build mismatches, one KEX startup-race flake). CI-equivalent rerun with `--features lab-surfaces`: **1961 passed, 30 skipped, 26 deselected, exit 0**.
- No independent ACVP/CAVP test-vector validation was reviewed; the repo claims ACVP/CT-KAT batteries, but this audit did not execute them.

### H.5 Documentation and maintainability

- The repo is unusually well documented, and `SECURITY.md`/README:36 are honest about non-accreditation.
- The 100/100 scorecard, “zero divergence,” and “tested against YubiKey/Luna/Nitrokey” claims are not supported by the evidence reviewed and conflict with the repo’s own critical findings.
- The lab/production split is conceptually good but poorly enforced at the CLI edges.

---

## I. Scorecard (0–100)

The score is an audit judgment, not a certification. Weights reflect what matters for a high-assurance military communications system.

| Category | Weight | Score | Rationale |
|---|---:|---:|---|
| Cryptographic primitives and protocol design | 20 | 15 | Strong ML-KEM/ML-DSA/SLH-DSA/AES-GCM/SHA-384 choices; custom composition; GCM IV defect; lab/prod mismatch |
| Authentication and trust establishment | 15 | 8 | Mutual ML-DSA-87 + pins + PSK in Rust; `--key-file` bypass; self-generated peer pin; TOFU/default hostname |
| Key management and hardware custody | 15 | 7 | Hardened keystore, zeroization, TPM sealed option; production disk seeds; HSM not enforced; 2/7 hardware; attestation flaw |
| Implementation quality and memory safety | 15 | 11 | Rust clippy clean, 267 tests, memory locking; Python monolith, duplicate crypto, broad exceptions |
| Replay, DoS, and traffic analysis | 10 | 7 | RFC 6479 window, state locking, pacing/chaff; not independently tested |
| Supply chain and CI | 10 | 7 | Blocking full suite green locally with CI-equivalent build; no cargo-audit/pip-audit; OSV fallback fail-open; one observed flake |
| Documentation truth and assurance | 10 | 3 | Honest disclosures exist, but 100/100, zero-disk, algorithm, and hardware claims are contradicted |
| Independent verification and evidence | 5 | 2 | Self-tests only; no external audit, no CMVP/CC/ATO, no hardware evidence |
| **Total** | **100** | **60** | **Engineering prototype; conditional for development/evaluation; no-go for sensitive production** |

**Grade bands used:**

- 0–20: unsafe / research only
- 21–40: early prototype
- 41–60: engineering prototype, not production-ready
- 61–80: production-capable with conditions and independent review
- 81–100: high-assurance / accreditation-grade evidence

**Confidence in the score:** Medium. The code inspection is substantial but partial; the CI-equivalent full suite passed (1961 passed, 30 skipped), but no independent review or hardware validation was possible. The score could move down if the unexamined modules contain serious defects, or up if the P0 issues are fixed and independently verified.

---

## J. Remediation Roadmap

### P0 — Before any controlled external evaluation or sensitive pilot (0–30 days)

| # | Action | Exit criterion |
|---|---|---|
| P0-1 | Enforce hardware-backed ML-DSA-87 custody in production; reject `--auth-sk-file` under `P2P_PRODUCTION`; make `run_tactical_station` use TPM/PKCS#11 or fail | Production launch with a disk seed fails; HSM/TPM path passes; no `.sk` seed written |
| P0-2 | Remove or production-gate `--key-file`/`--key-stdin`; enforce mutual auth in `cmd_channel`/`cmd_terminal` | `node --key-file` in production fails; `--require-mutual-auth` is checked outside KEX |
| P0-3 | Replace the deterministic GCM IV with durable/key-bound nonce management; unify the duplicate implementation | Cross-process/restart uniqueness test passes; no 4-byte-prefix construction |
| P0-4 | Fix TPM attestation: EK/AK chain, reject synthetic mode, check `hardware_mode`, bind nonce/transcript | Synthetic/self-signed quote is rejected; valid EK chain passes |
| P0-5 | Freeze a clean commit, build with `--features lab-surfaces`, rerun the full non-live suite and record the result | Full suite green on the frozen commit (achieved locally: 1961 passed, 30 skipped); blocking gate remains blocking |
| P0-6 | Correct the documentation: remove 100/100, zero-disk, and untested hardware claims; mark open findings | Docs-truth tests pass; evidence matrix published |

### P1 — Before ordinary sensitive production (30–90 days)

| # | Action | Exit criterion |
|---|---|---|
| P1-1 | Out-of-band peer key provisioning; remove locally generated peer identities; external/HSM-backed CA ceremony | Two-host enrollment works without copying private keys; self-signed root rejected in production |
| P1-2 | Add `cargo-audit` and `pip-audit`; fix OSV mirror fallback and require a signed, complete, fresh mirror | CI fails on a known-vulnerable pin; air-gap audit fails closed |
| P1-3 | Harden TLS/TOFU defaults: explicit fronting profile, hostname verification for direct mode, production PKI enforcement | MITM test with a valid-but-wrong-name cert fails; production without PKI fails |
| P1-4 | Triage Bandit lows and Python broad exceptions; reduce duplicate crypto code | Backlog burned down; no unjustified `except: pass` in security paths |
| P1-5 | Independent cryptographic review of the custom KEX/transcript/PCS and the ProVerif model-to-code gap | Reviewer report; findings fixed or accepted with rationale |
| P1-6 | Replace the KEX test’s fixed 1-second sleep with a bind-readiness wait; document the local lab-surfaces build requirement | KEX test passes repeatedly under load; local instructions match CI |

### P2 — Before military/classified or accreditation-grade use (90–180+ days)

| # | Action | Exit criterion |
|---|---|---|
| P2-1 | CMVP/FIPS 140-3 validation of the cryptographic module; CC/NDcPP evaluation; ATO | Certificate/evaluation report and ATO |
| P2-2 | Hardware validation on the claimed YubiKey 5 FIPS, Thales Luna, and Nitrokey devices; secure boot/VBS/HVCI/FIPS provider on target hosts | Reproducible hardware test logs and certificates |
| P2-3 | Independent penetration test, fuzzing, side-channel lab, fault injection, physical/TEMPEST assessment | Reports; critical/high findings closed |
| P2-4 | Key ceremony, disaster recovery, rotation, revocation, and multi-person control audit | Witnessed ceremony and runbooks |
| P2-5 | Continuous monitoring, SBOM/provenance verification, reproducible builds, incident response | Operational evidence |

**Do not claim “production-ready,” “military-grade,” “zero-disk,” “FIPS 140-3,” or “quantum-safe” in procurement material until the corresponding evidence exists.**

---

## K. Go/No-Go Decisions

| Use case | Decision | Conditions / rationale |
|---|---|---|
| **Development** | **GO** | Continue engineering. The Rust core is worth developing. Track F-01–F-13; do not deploy to sensitive environments. |
| **Internal testing** | **GO (lab only)** | Use synthetic data and `--lab`; no real credentials, no production peers. The Python lab path is acceptable for testing, not for security claims. |
| **Controlled external evaluation** | **CONDITIONAL GO** | Freeze a clean commit, disclose F-01–F-11, provide hardware, and scope the evaluation to the Rust path plus the Python lab path separately. P0-1–P0-4 should be fixed first, or explicitly excluded with a written rationale. No production data. |
| **Ordinary sensitive production** | **NO-GO** | F-01 (disk key custody), F-02 (mutual-auth bypass), F-03 (GCM IV), F-04 (attestation), F-05/F-10 (trust bootstrap/PKI), F-07/F-09 (assurance) remain open. No independent audit; the CI-equivalent full suite passed locally but self-tests are not adversarial evidence. |
| **Military / classified** | **NO-GO** | No ATO/CMVP/CC; hardware readiness 2/7; key custody not enforced; self-generated PKI; no TEMPEST/physical evaluation; documentation overclaims. The system is not eligible. |

**Bottom line:** ST2027 is a promising, technically ambitious prototype with a solid Rust cryptographic core. It is not a high-assurance system today. The fastest path to credibility is to fix the P0 control failures, publish honest evidence, and submit the Rust core and key-management design to independent review.

---

## Appendix A — Commands and Results

### A.1 Run to completion

| Command | Result |
|---|---|
| `python -m pytest tests/test_docs_truth_in_claims.py tests/test_cnsa2_hybrid_kex_2027.py tests/test_production_gate.py tests/test_legacy_quarantine.py tests/test_production_readiness_hardening.py -q --no-header` | **161 passed, 5 skipped**, exit 0 |
| `python -m pytest tests/test_production_gate.py::test_no_direct_production_environment_parsers` | **1 passed**, exit 0 |
| `cargo test --manifest-path rust_data_plane/Cargo.toml --lib --no-default-features` | **267 passed, 0 failed**, exit 0 |
| `cargo clippy --manifest-path rust_data_plane/Cargo.toml --all-targets -- -D warnings` | **exit 0**, “Finished dev profile” |
| `python -m py_compile` on all 154 root-level `.py` files | **0 failures** |
| `python secure_p2p.py selftest` | **8/8 passed**, exit 0; logs show software PQC implementation |
| `python secure_transmit_2027.py selftest` | **SELFTEST-OK**, exit 0; `hardware-posture: 2/7 HAVE`; `fips-probe: no provider` |
| `python -c "import hw_readiness; ... collect()"` | `strict_ok=False`; 2/7 HAVE (DMA, TPM); MISSING admin, Secure Boot, VBS/HVCI, HSM, FIPS |
| `python destroyer.py --help` | exit 0; logs `production_gate: FORCE-ARMED (destroyer_cli_default)` |
| `python scripts/audit_pins.py --offline` | 29 pins reported “no known vulns”; mirror contains only 4 entries |
| Simulated OSV outage with a mirror containing `CVE-TEST-0001` | Printed `OK ... no known vulns`, return 0 (fail-open) |
| TPM attestation probe under `P2P_PRODUCTION=1` | `hardware_mode=DEGRADED_SECONDARY_SIMULATION`; `verify=True` with self-generated Ed25519 key |
| `python -m pytest tests/ -q -m "not live" --tb=short` (default-feature binary) | **6 failed, 1955 passed, 30 skipped, 26 deselected**, exit 1, 1,062 s |
| `cargo build --offline --manifest-path rust_data_plane/Cargo.toml --features lab-surfaces --bin secure-transmit` then `python -m pytest tests/test_tactical_operations_suite.py -q --no-header` | build exit 0; **6 passed**, exit 0 |
| `python -m pytest tests/ -q -m "not live" --tb=short` (CI-equivalent `--features lab-surfaces` binary) | **1961 passed, 30 skipped, 26 deselected**, exit 0, 1,185 s |
| Isolated rerun of `test_kex_listen_connect_hybrid_establishment` plus manual two-process loopback probe | **1 passed**, exit 0; manual probe produced matching SAS and identical derived keys |
| `git rev-parse HEAD` / `git status --short` | `d21c280...`; only `cache/` untracked |
| Bandit over active tree | 0 high, 0 medium, **3,774 low** |

### A.2 Full-suite runs

- First run: `python -m pytest tests/ -q -m "not live" --tb=short` with a default-feature binary, log `C:\Users\des\AppData\Local\Temp\st2027_pytest_full.log`. Completed with **6 failed, 1955 passed, 30 skipped, 26 deselected** in 1,062 s. Five failures were the lab-surface build mismatch; the sixth was a flake (see F-08).
- Second run: the same command with the CI-equivalent `--features lab-surfaces` binary, log `C:\Users\des\AppData\Local\Temp\st2027_pytest_full_labsurf.log`. Completed **green: 1961 passed, 30 skipped, 26 deselected, 7 warnings in 1,184.88 s, exit 0**. This is a self-test result on the audit host, not independent validation.

### A.3 Not run

- Full Rust workspace/integration tests (`cargo test` without `--lib`).
- `cargo-audit`, `pip-audit` (not installed).
- `ts_rt` and `seL4` test suites.
- ProVerif models, Kani harnesses, `dudect` timing tests.
- Fuzz targets and long-running adversarial tests.
- Real TPM/HSM/smartcard/YubiKey/Luna/Nitrokey tests.
- Binary reverse engineering of `oqs.dll`/`libsodium.dll`/`.pyd`.
- External audit, CMVP, CC, SLSA verification, ATO.

### A.4 Environment notes

- Python 3.15 (local), Rust toolchain with clippy 0.1.99.
- Windows host; no elevated administrator rights; Secure Boot disabled; VBS/HVCI not enforcing.
- The audit host is not representative of a hardened military deployment; the 2/7 hardware result is a host fact, not proof that the project can never run on compliant hardware.

---

## Appendix B — Evidence Index

| Topic | File:line |
|---|---|
| README non-accreditation disclosure | `README.md:36` |
| README P-384 claim for Python orchestrator | `README.md:24` |
| README zero-disk/HSM claims | `README.md:917-924` |
| README 100/100 scorecard | `README.md:1469-1478` |
| README “RESOLVED” matrix | `README.md:1487-1500` |
| Self-audit verdict / critical mismatch | `AUDIT_REPORT_ST2027.md:12`, `148-155` |
| Security policy non-claims | `SECURITY.md:7-10` |
| Production gate / latch | `production_gate.py:65-183`, `207-220` |
| Python lab import | `secure_p2p.py:342`, `2463` |
| Lab-only chat | `secure_p2p.py:17161-17162` |
| Tactical provisioning / production command | `secure_p2p.py:16878-16919`, `16924-16967` |
| Rust auth key loader | `rust_data_plane/src/main.rs:221-265` |
| Rust `--key-file` bypass | `rust_data_plane/src/main.rs:3474-3482` |
| Rust `cmd_channel` | `rust_data_plane/src/main.rs:1966-1970` |
| Rust `cmd_terminal` | `rust_data_plane/src/main.rs:2867-2882` |
| Rust mutual-auth policy | `rust_data_plane/src/main.rs:283-304` |
| Rust production PKI pin check | `rust_data_plane/src/main.rs:3550-3552` |
| GCM IV construction | `cnsa_crypto_gateway.py:53-92` |
| Duplicate GCM IV | `platform_hsm_interface.py:23-47` |
| CJDAC2 compartment key + IV | `cjadc2_cross_domain_guard.py:261-266` |
| Synthetic PCRs | `platform_hsm_interface.py:6603-6682` |
| Attestation generation/verification | `platform_hsm_interface.py:6700-7060` |
| Lab chat attestation use | `secure_p2p.py:4886-4956` |
| TLS hostname default | `secure_transmit_2027.py:1190-1218` |
| Inner TOFU/PKI gate | `secure_transmit_2027.py:577-609` |
| Trust anchor policy | `trust_anchor.py:100-107` |
| OSV pin audit | `scripts/audit_pins.py:47-124` |
| Offline artifact | `compliance_reports/cve_scan_offline.json` |
| CI full-suite gate (blocking) | `.github/workflows/defense_ci.yml:438-442` |
| CI lab-surfaces build | `.github/workflows/defense_ci.yml:436` |
| CI failure-only advisory rerun | `.github/workflows/defense_ci.yml:445-449` |
| Self-signed cert | `credentials/base_alpha_cert.pem` |
| PKI manifest | `certs/pki_manifest.json` |
| HSM/TPM config | `config.json:44-52` |
| Legacy KEX alias | `hybrid_kex_legacy.py:339` |
| Legacy re-export | `hybrid_kex.py:33-45` |
| `destroyer.py` arm | `destroyer.py:34` |

---

## Appendix C — Glossary

- **CNSA 2.0:** NSA Commercial National Security Algorithm Suite 2.0; specifies ML-KEM-1024, ML-DSA-87, AES-256-GCM, SHA-384/SHA-512, and P-384 for the transition.
- **ML-KEM-1024:** FIPS 203 module-lattice key encapsulation mechanism, NIST security category 5.
- **ML-DSA-87:** FIPS 204 module-lattice digital signature, category 5.
- **SLH-DSA-256f:** FIPS 205 stateless hash-based signature, “fast” parameter set.
- **PCS:** post-compromise security (break-in recovery).
- **TOFU:** trust on first use; the first key seen is pinned without an external identity proof.
- **EK/AK:** TPM endorsement key / attestation key; the hardware root for remote attestation.
- **PCR:** TPM platform configuration register; measures firmware/boot state.
- **CMVP:** NIST Cryptographic Module Validation Program (FIPS 140-3).
- **CC/NDcPP:** Common Criteria / Network Device collaborative Protection Profile.
- **ATO:** Authority to Operate.

---

## Appendix D — What Would Change the Verdict

**Upgrade to “production-capable with conditions” (score ≥65) requires:**

1. F-01 fixed: hardware-backed ML-DSA-87 custody enforced in production, with no disk seeds.
2. F-02 fixed: `--key-file` removed/production-gated, and mutual-auth policy enforced in all data-plane commands.
3. F-03 fixed: durable/key-bound GCM nonce management with cross-process tests.
4. F-04 fixed: EK/AK-rooted attestation; synthetic/self-signed quotes rejected.
5. F-05/F-10 fixed: out-of-band peer provisioning and an externally anchored CA/HSM ceremony.
6. Full non-live suite green on a frozen commit (achieved locally with the CI-equivalent build); `cargo-audit`/`pip-audit` and a complete, signed OSV mirror still required.
7. Independent cryptographic review of the custom KEX/transcript/PCS and the ProVerif model-to-code gap.
8. Documentation corrected to match evidence; no 100/100 or untested-hardware claims.

**Downgrade to “unsafe” (score <40) would follow if:** an unexamined Rust/Python module contains a remotely triggerable memory-safety or auth-bypass defect, or if the self-signed PKI is used as the sole trust anchor in a production deployment.

**Military/classified upgrade** additionally requires CMVP/CC/ATO, TEMPEST/physical evaluation, hardware validation on the claimed devices, and an accredited key-management ceremony. No amount of in-repo self-testing substitutes for those.

---

*End of report.*
