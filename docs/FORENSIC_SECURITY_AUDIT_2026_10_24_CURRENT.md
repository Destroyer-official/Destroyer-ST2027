# Comprehensive Forensic Security Audit — Current Evidence Report

**Assessment window:** 2026-10-24 through 2026-10-25
**Repository:** `D:\code\Main_projects\p2p\p2p_6_1-26`
**Evidence baseline:** Git `db73f07e3b6e1d9a866e7c5f6e33545c3d77e94c`, plus the uncommitted audit remediations identified below
**Report status:** final for the stated evidence snapshot; not a certification, authorization to operate, or guarantee of security
**Classification:** technical security assessment; contains no operational secrets or mission data

---

## A. Executive verdict

### Bottom line

This repository contains substantial defensive engineering and many useful regression tests. The audit also found and corrected concrete implementation defects: unauthenticated group-state advancement, ambiguous group AAD encoding, counter-exhaustion mutation risks, permissive production-mode parsing, weak deployment gates, incomplete deployment archives, unsafe XML parsing, coarse-clock cache-eviction failure, and dependency/test-evidence gaps.

Those corrections improve the implementation. They do **not** establish military-grade security, formal verification, FIPS validation, reproducible builds, Signal/WhatsApp equivalence, or suitability for classified communications.

The strongest remaining concern is architectural: `rust_data_plane/src/group_ratchet.rs` is explicitly a project-specific sender-chain primitive, not MLS and not a complete authenticated group key-agreement protocol. It has no authenticated membership-commit protocol or dual-officer epoch authorization. Production assurance is additionally constrained by absent live two-terminal validation, non-hermetic tests, missing hardware/FIPS posture, secret copies across PyO3, and the absence of an independent protocol review.

### Deployment decisions

| Deployment class | Decision | Conditions / rationale |
|---|---|---|
| Development and isolated internal lab testing | **CONDITIONAL GO** | Non-production data only; explicit lab configuration; network isolation; disposable identities and keys; no operational mission traffic. Clean package self-test passes in this profile. |
| Controlled external security evaluation | **CONDITIONAL GO, tightly scoped** | Authorized test environment, synthetic data, monitored endpoints, documented rollback, no classified or operationally sensitive information, and no claim that evaluation constitutes certification. |
| Pilot or production with ordinary sensitive data | **NO-GO at present** | First close the release blockers in Section J: hermetic full-suite evidence, live two-terminal tests, operational/hardware readiness, and independent protocol review. |
| Military, classified, strategic-command, or safety-critical operational use | **NO-GO** | The present evidence cannot support the required protocol, implementation, supply-chain, endpoint, operational, and accreditation assurance. |

### Quantified current assurance

**Overall current security assurance: 54/100.** This is an evidence-based engineering judgement, not a probability of compromise, compliance score, or certification. Dimension scores are reported separately in Section I so stronger dependency and test results cannot conceal weaker protocol and operational readiness.

### Remediation outcome

The audit remediated the demonstrated defects that could be corrected safely without silently changing persisted credentials, inventing a new group protocol, or claiming unavailable hardware/accreditation. Open items that require architectural design, migration, external validation, or operational evidence remain open. “Fix everything” cannot honestly mean replacing an unreviewed custom protocol with an unreviewed rewrite or changing password KDF parameters without a compatibility plan.

---

## B. Repository coverage and method

### Evidence snapshot and change control

- Final Git HEAD: `db73f07e3b6e1d9a866e7c5f6e33545c3d77e94c` (`Merge pull request #1 from Destroyer-official/audit/destroyer-st2027-verified-fixes`, 2026-10-25 21:48:12 +0530).
- `git ls-files` reported **654 tracked files**, including **359 Python** and **37 Rust** paths.
- The starting baseline was earlier `9ca1480` with 606 files. The repository changed externally during the audit; findings and tests were therefore revalidated against the later tree where practical.
- Uncommitted audit-owned changes include the dependency pins, group/data-plane hardening, XML parser correction, package manifest correction, tests, hash-manifest update, and narrowed Rust documentation. `docs/audit/PROGRESS.md`, `docs/audit/index.md`, and other externally introduced `docs/audit/*` material were preserved and were **not** accepted as independent evidence.
- This report applies to current HEAD plus those working-tree edits. It is not a signed attestation over an immutable source archive.

### Coverage techniques

1. Enumerated tracked and relevant non-ignored files; reviewed architecture, trust boundaries, security-sensitive modules, tests, deployment tooling, native interfaces, and documentation.
2. Searched for cryptographic construction, state mutation, parser, credential, deployment-gate, and resource-lifetime hazards.
3. Ran targeted exploit/regression tests, a broad Python selection split into four alphabetical shards, focused reruns, Rust unit/property-double tests, Clippy, formatting checks, compile checks, dependency audits, Bandit, and candidate secret scanning.
4. Built and exercised a clean deployment directory with `PYTHONPATH=` and `PYTHONNOUSERSITE=1`.
5. Retrieved current primary standards and protocol documentation. The requested “2027+ research” was interpreted as current verifiable research available during this assessment, not invented future publications.

### Material limitations

- Repository-wide automated coverage and targeted manual review are **not** equivalent to a line-by-line independent review of every file or proof that every reachable path was exercised.
- The original monolithic Python run exceeded the five-minute execution limit. The broad run was sharded; failures were corrected and rerun in focused sets. The effective total below is reconciled evidence, not one monolithic run against one immutable commit.
- Tests modified source/receipt files and created `out/`, `compliance_dossier/`, and scripts. Newly observed tracked side effects were restored. The suite is therefore **not hermetic**.
- No live two-terminal operational test was available; the corresponding test remained skipped.
- Hardware-attested, kernel/seL4, side-channel, fault-injection, traffic-analysis, fuzzing, and production deployment claims were not independently validated on target equipment.
- Ordinary `cargo test` executed harnesses and property doubles. It did **not** execute Kani formal proofs.
- `notupload/` was compile-checked and treated as quarantined repository content; it was not rewritten or promoted into the supported runtime.

### Evidence artifacts

| Artifact | Meaning |
|---|---|
| `audit_pytest_shard_1.log` … `audit_pytest_shard_4.log` | Original broad sharded Python evidence and initial failures |
| `audit_rust_final.log` | Targeted rustfmt, Clippy, Rust tests, and RustSec evidence |
| `audit_bandit.json` | Final main-tree Bandit result |
| `audit_bandit_sel4.json` | Focused XML remediation scan |
| `audit_pip_dependencies.log` | Python dependency advisory result |
| `audit_compileall_main.log` | Empty log from successful main-tree compile check |
| `audit_compileall_notupload.log` | 22 malformed quarantined Python files |
| `audit_cargo_fmt_global.log` | Crate-wide formatting differences |
| `audit_secret_scan.json` | Merged candidate-only secret scan |
| `audit_reproducible_build.log` | Existing-artifact/signature/hash verification, not a rebuild |

---

## C. Architecture and trust boundaries

### Observed architecture

- **Application/orchestration plane:** a large Python codebase handles identity, peer orchestration, policy, hardware integration, tactical functions, deployment checks, and user workflows.
- **Native data plane:** Rust modules implement framing, AEAD, replay handling, padding/chaff, handshake/ratchet components, key storage, attestation, and tactical support.
- **FFI/native-library boundary:** PyO3 and ctypes connect Python to Rust and native cryptographic libraries. This is a security boundary, not merely an implementation detail.
- **Network boundary:** peers, relays, DHT/TLS/UDP paths, and tactical inputs are untrusted until authenticated and authorized. Availability and traffic-analysis resistance remain deployment-dependent.
- **Endpoint/hardware boundary:** OS memory, CPython GC, TPM/HSM, Secure Boot, VBS/HVCI, seL4 domains, and native-library loading have different assurance properties. Software labels do not collapse those boundaries.
- **Build/release boundary:** source, pinned dependencies, vendored DLLs, signatures, SBOMs, generated receipts, and packaged runtime files must all agree. A receipt produced on the same host is not independent provenance.

### Principal assets

Session and identity private keys; group epoch/chain secrets; message plaintext; roster and clearance metadata; anti-replay/counter state; trust-anchor and enrollment data; officer-authorization state; audit evidence; signing keys; deployment configuration; and availability of command/communication paths.

### Adversary model used

The assessment considers network attackers able to observe, drop, replay, reorder, and modify traffic; malicious or compromised peers; local unprivileged attackers and post-compromise forensic access where relevant; malicious deployment configuration; dependency/artifact tampering; and operator error. It does not assume that encryption alone protects a fully compromised endpoint, that an authenticated peer is authorized for every action, or that a self-signed local receipt proves a clean build.

---

## D. Critical remediated defects

### D-01 — Receiver group state could advance before authentication

**Severity before fix:** High
**Confidence:** High
**Status:** **FIXED in the reviewed implementation**

- **Evidence:** `SovereignGroupRatchet::decrypt_group_message`, `rust_data_plane/src/group_ratchet.rs:214-265`.
- **Former defect/impact:** a forged frame could mutate the receiver’s chain position before AES-GCM authentication, causing desynchronization and denial of service and making later honest traffic fail.
- **Attack prerequisites:** ability to submit a forged group frame for a known sender; no valid group key required for the state-corruption attempt.
- **Correction:** clone candidate state, advance only the candidate, authenticate group/epoch/sender/sequence-bound AAD, then commit at line 264. Honest traffic after a forged attempt is covered by the regression at lines 374-389.
- **Verification:** final Rust suite passed; the focused honest-message-after-forgery regression passed.

### D-02 — Group AAD was not canonical across variable-length identifiers

**Severity before fix:** High
**Confidence:** High
**Status:** **FIXED; migration intentionally incompatible**

- **Evidence:** `message_aad`, `rust_data_plane/src/group_ratchet.rs:47-65`; profile declaration at lines 24-30.
- **Former defect/impact:** concatenation without unambiguous field boundaries allowed different field tuples to produce the same AAD byte string, undermining context binding.
- **Correction:** v2 AAD includes protocol ID, 32-bit big-endian group/sender lengths, epoch, sender, and sequence with checked conversions.
- **Migration impact:** legacy v1 frames are intentionally rejected. Peers must upgrade together or use a separately reviewed, authenticated transition profile. Silent fallback must not be introduced.

### D-03 — Counter/epoch exhaustion and nonce-state safety

**Severity before fix:** High
**Confidence:** High
**Status:** **FIXED**

- **Evidence:** outbound staged commit at `group_ratchet.rs:176-209`; checked epoch advance at lines 271-297; `SecureEngine::seal_msg` at `rust_data_plane/src/lib.rs:165-196`; checked ratchet transitions in `rust_data_plane/src/ratchet.rs:104-159`.
- **Former defect/impact:** wraparound or partial mutation near `u64` exhaustion could permit nonce/key reuse or leave a session unusable after an error.
- **Correction:** checked arithmetic, refusal at exhaustion, no wire emission on failure, and state commit only after successful cryptographic processing.
- **Verification:** sequence/epoch exhaustion and rollback regressions passed in the final Rust run.

### D-04 — Production posture could fail open on operator spelling errors

**Severity before fix:** High
**Confidence:** High
**Status:** **FIXED**

- **Evidence:** `production_gate._wants`, `production_gate.py:90-110`; sticky behavior at lines 113-146.
- **Reproduction before fix:** an unknown non-empty value such as `P2P_PRODUCTION=tru` did not reliably select strict posture.
- **Impact:** a typo could silently disable production controls.
- **Correction:** only explicit falsey values select lab mode; unknown non-empty values arm production and emit a critical diagnostic. Once armed, production remains latched.
- **Regression:** `tests/test_audit_forensic_remediations.py:137-158` resets test-only latch state before testing a fresh falsey-only posture. `reset_for_tests()` is isolated at `production_gate.py:171-184`.

### D-05 — Deployment checks did not adequately gate host/TLS posture

**Severity before fix:** High
**Confidence:** High
**Status:** **FIXED as a gate; host readiness remains OPEN**

- **Evidence:** `verify_deployment.py::verify_host_posture`, lines 757-774 and following; TLS 1.3 setup failure handling at lines 501-528.
- **Former impact:** production could report readiness despite unavailable required host posture or TLS 1.3 runtime support.
- **Correction:** production host-posture detection failures and absent TLS 1.3 support fail closed; lab behavior remains advisory where appropriate.
- **Residual:** the evaluated clean package reported only **3/7 HAVE** hardware posture and no FIPS provider. The corrected gate does not create the missing controls.

### D-06 — Unsafe XML import in seL4 manifest handling

**Severity before fix:** Medium
**Confidence:** High
**Status:** **FIXED**

- **Evidence:** `sel4_microkit_manifest.py:24-26` retains stdlib ElementTree for generation and imports `defusedxml.ElementTree.parse`; `from_xml_file` calls it at lines 225-227.
- **Former impact:** parsing an attacker-influenced manifest could expose XML entity/DTD hazards.
- **Correction and regression:** valid XML roundtrip and DOCTYPE/ENTITY rejection are tested at `tests/test_sel4_sovereign_appliance.py:86-104`.
- **Verification:** focused deployment/seL4 tests: **9 passed in 4.90s**. `audit_bandit_sel4.json`: zero medium/high findings and no errors; one low B405 remains for the generation-only stdlib import. Main Bandit’s former B314 medium is resolved.

---

## E. Complete finding register

Severity reflects credible impact in context, not scanner labels. Confidence reflects evidence quality. “Fixed” means the specific implementation defect was corrected and regressed; it does not imply the surrounding subsystem is production-approved.

### E-1 Remediated implementation and evidence findings

| ID | Severity / confidence | Exact evidence | Defect and demonstrated or plausible impact | Remediation / regression | Status |
|---|---|---|---|---|---|
| F-01 | High / High | `group_ratchet.rs:214-265` | Pre-auth receiver state mutation; forged traffic could desynchronize honest peers. | Candidate state, authenticate, then commit; honest-after-forgery regression. | Fixed |
| F-02 | High / High | `group_ratchet.rs:24-30,47-65` | Ambiguous legacy AAD field boundaries. | Canonical length-prefixed v2 AAD; old profile refused. | Fixed; migration open |
| F-03 | High / High | `rust_data_plane/src/group_ratchet.rs:91-109,176-209,271-297`; `rust_data_plane/src/lib.rs:165-196`; `rust_data_plane/src/ratchet.rs:104-159` | Counter wrap/exhaustion and partial-state risks. | Checked counters and atomic candidate commit; exhaustion tests. | Fixed |
| F-04 | High / High | `production_gate.py:90-146` | `tru`-style typo could select weaker posture. | Unknown non-empty values arm/latch production; falsey-only test reset. | Fixed |
| F-05 | High / High | `verify_deployment.py:501-528,757-774` | Missing TLS 1.3/host detection could pass production gate. | Fail-closed production checks. | Fixed gate; readiness open |
| F-06 | Medium / High | `secure_p2p.py:145-152` | Import-time Windows stream replacement could discard stream state/capabilities. | Non-destructive `reconfigure` with bounded exception handling. | Fixed |
| F-07 | Medium / High | `requirements.txt:2-55`; `requirements-test.txt:1-22` | Incomplete/unpinned runtime and test dependency evidence. | Runtime hashes and complete test pins; hash-locked clean install succeeded. | Fixed for tested set |
| F-08 | Medium / High | `operational_security.py:712-728` | Equal coarse Windows timestamps could prevent bounded-message eviction, enabling memory growth. | Initialize oldest inserted entry before timestamp refinement; capacity regression rerun. | Fixed |
| F-09 | Medium / High | `scripts/package_deployment.py:22-39`; `tests/test_deployment_package.py:15-39` | Clean archive omitted verifier/hardware-readiness/signature files and could not self-test. | Added required files; automated clean build/hash/self-test. | Fixed |
| F-10 | Medium / High | `sel4_microkit_manifest.py:24-26,225-227`; `test_sel4_sovereign_appliance.py:86-104` | Unsafe XML entity handling. | Defused parser; valid and malicious XML regressions. | Fixed |
| F-11 | Medium / High | `critical_modules.hashes`, entry for `rust_data_plane/src/main.rs` | Hash manifest no longer matched remediated critical source. | Recomputed using verifier CRLF-normalized semantics; existing-artifact verifier passed. | Fixed for snapshot |
| F-12 | Low / High | `docs/RUST_CORE.md:1-21,45-90,117-177`; `lib.rs:34-39` | Overbroad frozen-reference, PQ3, FFI-secrecy, and zeroization claims could mislead deployment decisions. | Narrowed claims and documented current evidence boundaries. | Fixed documentation |
| F-13 | Low / High | `requirements-test.txt:5-6`; `tests/test_audit_forensic_remediations.py:147-155` | Test dependencies and sticky-state isolation produced false failures/misleading evidence. | Completed pins; explicit test-only reset; wording states sharded/focused evidence. | Fixed |

### E-2 Open design, assurance, and operational findings

| ID | Severity / confidence | Exact evidence and prerequisites | Impact: demonstrated vs plausible | Required disposition |
|---|---|---|---|---|
| O-01 | **High / High** | `group_ratchet.rs:1-15,165-172,268-297`; any caller able to trigger local roster/epoch APIs; outer authorization not implemented here. | **Demonstrated design fact:** no authenticated membership commits, dual-officer epoch authorization, or complete group AKE. **Plausible impact:** unauthorized roster/epoch changes or group-state forks if outer policy is absent/bypassed. | Adopt a reviewed group protocol/architecture (MLS where suitable), define AS/DS and application authorization, and independently review the composition. Do not expose this primitive as MLS-equivalent. |
| O-02 | Medium / High | `group_ratchet.rs:14-15,229-245`; delayed frames arriving after catch-up. | **Demonstrated:** skipped message keys are discarded, so delayed out-of-order messages cannot be recovered. Availability/interoperability loss on reordering networks. | Specify bounded skipped-key retention and expiry or explicitly require ordered/reliable transport; test adversarial reordering. |
| O-03 | Medium / High | `group_ratchet.rs:24-25`; deployed peers still emitting v1. | **Demonstrated compatibility decision:** v1 frames fail under v2. Availability during migration is expected; accepting ambiguous v1 would preserve the defect. | Inventory peers, stage a versioned cutover, reject downgrade, retain rollback artifacts, and test mixed-version behavior without weakening v2. |
| O-04 | **High / High** | `docs/RUST_CORE.md:80-90`; `audit_rust_final.log:137-184`; independent reviewers not part of supplied evidence. | **Demonstrated evidence gap:** ordinary tests, not Kani proofs or independent protocol verification. Custom constructions may contain flaws invisible to unit tests. | Independent cryptographic/protocol review; executable Tamarin/ProVerif or computational models with explicit assumptions; execute Kani where properties are in scope. |
| O-05 | **High / High** | `audit_pytest_shard_3.log:1579`; absent external `run_two_terminals_secure_p2_test.py`. | **Demonstrated:** no live two-terminal end-to-end evidence. Real NAT, timing, concurrency, rekey, recovery, and deployment behavior remain unverified. | Implement a repeatable two-host test matrix covering loss, replay, reorder, rekey, restart, rollback, and hostile input. |
| O-06 | **High / High** | Clean `out/audit_deploy` self-test observation: hardware posture **3/7 HAVE**, no FIPS provider, lab TOFU warnings; `verify_deployment.py:757-774`. | **Demonstrated environment gap:** lab self-test success is not production posture. Sensitive operations lack the asserted hardware/validated-crypto foundation. | Deploy on qualified hardware, verify Secure Boot/TPM/VBS/HVCI as required, use appropriately validated modules where mandated, and remove TOFU from high-assurance enrollment. |
| O-07 | Medium / High | Test side effects observed in source/receipts plus generated `out/`, `compliance_dossier/`, and scripts. | **Demonstrated:** suite is not hermetic; results can contaminate later tests or integrity receipts. | Isolate all writes in temp dirs/copy-on-write fixtures, snapshot/restore state automatically, then run a clean monolithic suite twice against an immutable commit. |
| O-08 | Medium / High | `audit_compileall_notupload.log`: 22 malformed Python files; examples at log lines 1-17 and 37-92. | **Demonstrated:** quarantined content is syntactically broken. Impact is conditional on import/packaging; accidental promotion could cause failure or unreviewed code execution. | Keep out of release archives and import paths; quarantine with a manifest, or repair/review separately. Do not silently treat it as supported source. |
| O-09 | Low / High | `audit_cargo_fmt_global.log`: 731 diff lines across `acd.rs`, `cookie.rs`, `ffi.rs`, `main.rs`, `memory_guard.rs`, `policy.rs`, `replay.rs`, `tpm_nv.rs`, `zero_trust.rs`, `tests/kani_harness.rs`. | **Demonstrated quality gate failure**, not a demonstrated vulnerability. Inconsistent formatting raises review/maintenance cost. | Apply crate-wide formatting in a separate mechanical change and enforce CI; review generated diff before merge. |
| O-10 | Medium / High | `audit_reproducible_build.log:12-49`; local signed receipts and SBOM signatures. | **Demonstrated:** script validates existing artifacts; it does not rebuild or compare independent outputs. Its “100% Verified” text is not reproducibility or SLSA evidence. | Produce hosted, signed provenance and independent clean rebuilds. SLSA L2 needs hosted-platform signed provenance; L3 additionally needs hardened isolation and signing-secret protection. |
| O-11 | Informational / High | `audit_secret_scan.json`: 74 candidates in 15 files across 705 scanned tracked/non-ignored files. | **Triage result:** reviewed hits were KAT vectors, HKDF labels, hashes/receipts, test dummies, generated scan output, duplicate deployment content, and a WireGuard placeholder. No confirmed live credential was found; absence was not proved. | Keep scanning in CI with scoped suppressions and entropy review; rotate immediately if a real credential is later identified. |
| O-12 | Low–Medium / High | PBKDF2-HMAC-SHA512 210,000 iterations at `air_gapped_operation.py:322`, `audit_logging_system.py:102`, `critical_release.py:29`, `nc3_nuclear_command.py:1521,1556`, `utils/error_handler.py:344`, `secure_key_manager.py:1159`, `secure_enclave_key_storage.py:1166,1252,1412,1427`, `tactical_key_provisioner.py:68,108`. | **Demonstrated hardening gap:** current OWASP lists 220,000. This does not make 210,000 immediately exploitable; risk depends on password entropy and attacker access to verifiers. | Add versioned KDF metadata, benchmark target latency, migrate on successful unlock/authentication, retain verification compatibility, and test rollback. Do not globally replace constants without migration. |
| O-13 | Medium / High | `rust_data_plane/src/lib.rs:34-39,134-160,390-457`; `docs/RUST_CORE.md:12-21`. | **Demonstrated boundary:** KEX session keys and derived secrets return to CPython. **Plausible impact:** interpreter heap/GC copies extend secret lifetime and undermine Rust-only erasure claims. | Keep secret-consuming operations native where feasible; otherwise document exposed copies, minimize lifetimes, use mutable buffers carefully, and assess dumps/forensics. |
| O-14 | Medium / High | `docs/RUST_CORE.md:12-21,80-90`; Python immutable `bytes`, allocator, swap, crash dumps, compiler optimizations. | **Assurance limit:** software zeroization cannot prove every copy erased from RAM/storage or defend a concurrently compromised endpoint. | Threat-model physical/post-compromise access; use locked memory and hardware-backed keys where appropriate; test dump/swap behavior; avoid absolute erasure claims. |
| O-15 | Medium / High | Effective Python skips: 20 missing legacy twins, 2 Linux/hardware cases, 1 absent two-terminal script; unexecuted fuzz/live/platform checks. | **Demonstrated coverage limit:** green totals do not cover these behaviors. Missing legacy twins are not automatically vulnerabilities, but they reduce comparison assurance. | Restore maintained comparison fixtures or retire obsolete tests explicitly; execute target-platform hardware and fuzz campaigns with reproducible corpora. |

### E-3 Reproduction index for remediated findings

These are minimal reproduction conditions, followed by the regression evidence now used. In E-1, bare `group_ratchet.rs`, `lib.rs`, and `ratchet.rs` refer to files under `rust_data_plane/src/`; bare test filenames refer to `tests/`.

- **F-01:** submit a structurally valid forged frame ahead of an honest frame; before remediation the forged attempt could shift receive state. Now assert authentication failure, unchanged state, and successful honest decrypt (`group_ratchet.rs:374-389`).
- **F-02:** construct legacy AAD over boundary-shifting variable-length identifiers; v1 could collide while v2 length-prefixes each identifier. Run v2 roundtrip/tamper tests and intentionally reject legacy v1 frames.
- **F-03:** place send/receive sequence or epoch at its maximum and invoke the operation; require an error, no ciphertext, and byte-equivalent pre-call counters/state. Covered by Rust exhaustion/rollback regressions.
- **F-04:** set `P2P_PRODUCTION=tru`; require `is_production()` to return true and latch. Then use the test-only reset and explicit falsey values to confirm a fresh lab posture (`tests/test_audit_forensic_remediations.py:137-158`).
- **F-05:** simulate posture-detection failure and remove TLS 1.3 runtime support under production; require deployment verification to fail. Relevant focused gate tests were rerun in the broad/focused Python evidence.
- **F-06:** import with a stateful Windows stream exposing `reconfigure`; require the same stream object and preserved capabilities rather than replacement. The final main compile and Python regressions passed.
- **F-07:** install in a clean environment using `pip install --require-hashes -r requirements.txt`; require every selected artifact to match a pin. Installation succeeded; sharded/focused tests validated `requirements-test.txt` on 2026-10-25.
- **F-08:** fill `MessageExpirationManager` to capacity with equal `created_at` timestamps, then insert another item; require size to remain bounded and one oldest item to be expelled (`operational_security.py:712-728`).
- **F-09:** build into an empty directory, clear `PYTHONPATH`, disable user site packages, and run `secure_transmit_2027.py selftest` from that directory. `tests/test_deployment_package.py:15-39` automates this and `SELFTEST-OK` was observed.
- **F-10:** parse valid exported XML, then XML containing DOCTYPE/ENTITY; require valid MILS invariants and `EntitiesForbidden`, respectively (`tests/test_sel4_sovereign_appliance.py:86-104`).
- **F-11:** run `scripts/verify_reproducible_build.py` after the source remediation; before updating the manifest the critical-file gate would mismatch. After the scoped `main.rs` entry update, all four critical hashes and both DLL/SBOM signature sets passed (`audit_reproducible_build.log:30-45`).
- **F-12:** compare documentation claims with actual PyO3 returns at `rust_data_plane/src/lib.rs:390-457`; the correction is documentary, verified by source review rather than presented as a runtime vulnerability test.
- **F-13:** arm the production latch, then evaluate explicit falsey values without resetting; the original test leaked state and failed. The explicit test-only reset fixed isolation and the test passed (`tests/test_audit_forensic_remediations.py:147-155`).

---

## F. Cryptographic and protocol assessment

### Standards alignment

NIST FIPS 203 defines ML-KEM, FIPS 204 defines ML-DSA, and FIPS 205 defines SLH-DSA. Algorithm names and parameter sizes alone do not prove a secure composition or a validated implementation. [NIST FIPS 203](kimi-cite://web?url=https%3A%2F%2Fcsrc.nist.gov%2Fpubs%2Ffips%2F203%2Ffinal "citation"), [NIST FIPS 204](kimi-cite://web?url=https%3A%2F%2Fcsrc.nist.gov%2Fpubs%2Ffips%2F204%2Ffinal "citation"), [NIST FIPS 205](kimi-cite://web?url=https%3A%2F%2Fcsrc.nist.gov%2Fpubs%2Ffips%2F205%2Ffinal "citation")

The group implementation uses AES-256-GCM. GCM is an AEAD mode when used within its nonce, key-use, and verification requirements; the remediated counter and AAD work addresses composition hazards rather than alleging AES-GCM itself is broken. NIST has announced an intention to revise SP 800-38D, so current guidance should be rechecked at release time. [NIST SP 800-38D](kimi-cite://web?url=https%3A%2F%2Fcsrc.nist.gov%2Fpubs%2Fsp%2F800%2F38%2Fd%2Ffinal "citation")

Current TLS 1.3 is specified by RFC 9846, which obsoletes RFC 8446 and tightens requirements including key-share reuse and key-update limits. RFC 9325 remains BCP 195 but its info page records later updates; release guidance must use the current RFC graph rather than a frozen citation. [RFC 9846](kimi-cite://web?url=https%3A%2F%2Fwww.rfc-editor.org%2Finfo%2Frfc9846 "citation"), [RFC 9325](kimi-cite://web?url=https%3A%2F%2Fwww.rfc-editor.org%2Finfo%2Frfc9325 "citation")

RFC 10024 standardizes only `X25519MLKEM768`, `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024` for its TLS hybrid profile. It explicitly warns that the analysis depends on the TLS transcript and cannot simply be transferred to arbitrary hybrid protocols. The repository’s custom hybrid compositions therefore require their own binding and review evidence. [RFC 10024](kimi-cite://web?url=https%3A%2F%2Fwww.rfc-editor.org%2Finfo%2Frfc10024 "citation")

### Group protocol versus MLS

MLS (RFC 9420) defines authenticated proposals/commits, linear epochs, membership state, key schedules, and an Authentication Service/Delivery Service model. RFC 9750 makes clear that application authorization policy—such as administrator or dual-officer approval—must be consistently enforced above MLS; MLS itself does not invent that policy. This project’s sender-chain primitive provides neither MLS nor that missing application layer. [RFC 9420](kimi-cite://web?url=https%3A%2F%2Fwww.rfc-editor.org%2Finfo%2Frfc9420 "citation"), [RFC 9750](kimi-cite://web?url=https%3A%2F%2Fwww.rfc-editor.org%2Finfo%2Frfc9750 "citation")

**Assessment:** the v2 primitive is materially safer than the audited v1 implementation, but security of a local HKDF/AEAD transform is not security of group membership, authorization, agreement, recovery, or asynchronous delivery.

### Authentication and password-derived protection

NIST SP 800-63B-4 requires salted suitable password hashing, recommends costs as high as practical, and recommends storing scheme/cost metadata for migration. AAL3 requires phishing-resistant public-key authentication with a non-exportable private key, replay resistance, authentication intent, and validated cryptography in the relevant government context. [NIST SP 800-63B-4](kimi-cite://web?url=https%3A%2F%2Fpages.nist.gov%2F800-63-4%2Fsp800-63b.html "citation")

OWASP currently lists 220,000 iterations for PBKDF2-HMAC-SHA512 and describes versioned work-factor upgrades. The repository’s 210,000-iteration sites are a modest hardening gap, not an emergency plaintext-password finding. Migration must preserve existing verifiers and encrypted backups. [OWASP Password Storage Cheat Sheet](kimi-cite://web?url=https%3A%2F%2Fcheatsheetseries.owasp.org%2Fcheatsheets%2FPassword_Storage_Cheat_Sheet.html "citation")

### Secret lifetime and side channels

Rust zeroization, locked memory, and constant-time primitives reduce exposure. They do not erase CPython-owned copies, every allocator copy, swap, crash dumps, or an attacker already inside the process. No side-channel or fault-injection resistance claim should extend beyond the measurements actually performed.

---

## G. Signal and WhatsApp comparison

This comparison is architectural and evidence-based; it is not a claim that any external product is flawless.

| Property | Signal’s published design | WhatsApp published key-transparency design | This repository’s current evidence |
|---|---|---|---|
| Initial PQ key establishment | PQXDH revision 3 provides PQ forward secrecy but still relies on discrete logarithm for mutual authentication; active quantum authentication is explicitly not provided. | Uses the Signal protocol family for E2EE; the cited source here focuses on key-directory consistency, not a new KEX proof. | Multiple project-specific hybrid paths exist; tests and KAT/interoperability evidence do not substitute for independent composition proofs. |
| Ongoing ratcheting | Double Ratchet revision 4 includes SPQR and Triple Ratchet for continuing PQ ratcheting, bounded skipped-message-key handling, and discard-on-authentication-failure semantics. | Built around deployed Signal-protocol mechanisms plus service infrastructure. | Fresh-KEM/ratchet components and the group sender-chain primitive are not SPQR/Triple Ratchet equivalence claims. |
| Out-of-order delivery | Defines skipped-key storage with `MAX_SKIP` bounds. | Mature asynchronous messaging behavior is deployment-specific and not proven by the KT article. | Group catch-up discards skipped keys; delayed messages are unsupported. |
| Group membership | MLS is a separate standards-track group AKE architecture, not synonymous with Signal’s 1:1 ratchet. | Large service identity and delivery infrastructure; KT complements key verification. | No authenticated membership-commit protocol or complete group AKE in `group_ratchet.rs`. |
| Identity-key consistency | Manual identity fingerprint/safety-number mechanisms remain relevant to PQXDH authentication. | Append-only AKD plus third-party public audit record; QR/security-code verification remains an additional option. | TOFU/lab enrollment and local trust stores exist in parts; no independently operated public key-transparency/auditor system was demonstrated. |
| Verification evidence | Public specifications cite formal analyses and years of external review; exact assurance still depends on implementation/deployment. | Public engineering design and deployed auditor ecosystem. | Broad tests and scans, but no independent protocol review or comparable operational evidence. |

Signal’s PQXDH documentation is especially important because it refutes the simplistic claim that “post-quantum” automatically covers both confidentiality and active authentication. [Signal PQXDH revision 3](kimi-cite://web?url=https%3A%2F%2Fsignal.org%2Fdocs%2Fspecifications%2Fpqxdh%2F "citation")

Signal Double Ratchet revision 4, dated 2025-11-04, requires discarding state changes on authentication failure and documents skipped-key and ongoing PQ mechanisms; the group remediation follows the first principle, but does not implement the full protocol. [Signal Double Ratchet revision 4](kimi-cite://web?url=https%3A%2F%2Fsignal.org%2Fdocs%2Fspecifications%2Fdoubleratchet%2F "citation")

WhatsApp key transparency uses an append-only Auditable Key Directory and third-party public audit record, explicitly complementing rather than replacing QR/security-code verification. A later Meta deployment article confirms the AKD/auditor model and its extension to Messenger. [Meta: WhatsApp key transparency](kimi-cite://web?url=https%3A%2F%2Fengineering.fb.com%2F2023%2F04%2F13%2Fsecurity%2Fwhatsapp-key-transparency%2F "citation"), [Meta: key transparency deployment and auditor model](kimi-cite://web?url=https%3A%2F%2Fengineering.fb.com%2F2025%2F11%2F20%2Fsecurity%2Fkey-transparency-comes-to-messenger%2F "citation")

**Conclusion:** the repository should not advertise “better than Signal,” “PQ3 superiority,” or WhatsApp-equivalent identity assurance. Its current differentiators are custom deployment/tactical controls, which themselves increase the review burden.

---

## H. Engineering quality and verification results

### Python tests

Original broad shards:

1. `2 failed, 484 passed, 7 skipped`
2. `2 failed, 524 passed, 12 skipped, 4 errors`
3. `261 passed, 5 skipped`
4. `245 passed, 4 skipped, 17 deselected`

All eight unresolved failure/error cases were remediated and rerun. That reconciles the original broad evidence to **1,522 passed, 28 skipped, 17 deselected**. Cargo-enabled focused reruns recovered five skips; the new clean-package test added one unique pass; the XML regression added one more. **Effective unique evidence: 1,529 passed, 23 skipped, 17 live-deselected.**

This is a reasoned sharded-plus-focused total, **not** an executed monolithic result. Remaining skips comprise 20 missing legacy comparison twins, two Linux/hardware-specific cases, and one absent external two-terminal script.

### Rust and native checks

Final `audit_rust_final.log` evidence:

- Targeted rustfmt check on remediated files: passed.
- `cargo clippy --lib --locked -- -D warnings`: passed.
- Library tests: **119 passed**.
- `tests/kani_harness.rs` ordinary tests/property doubles: **37 passed**.
- Binary and doc tests: zero tests.
- RustSec: loaded **1,352 advisories**, scanned **105 crates**, exited successfully with no reported vulnerability.
- Crate-wide `cargo fmt --check`: **failed with formatting differences** in ten files; see O-09. This is not counted as a security regression.

The 37 harness tests are ordinary executable tests, not 37 completed formal proofs.

### Dependency, static, and parser checks

- `pip_audit -r requirements.txt`: **No known vulnerabilities found**. This is point-in-time advisory coverage, not proof of dependency safety.
- Hash-locked `pip install --require-hashes -r requirements.txt`: succeeded in the clean audit environment.
- Main Bandit: **2,473 results — 2,473 LOW, 0 MEDIUM, 0 HIGH, 0 errors**. Most are low-severity `assert` usage: **2,147 B101**. Other leading IDs: B603 126, B110 115, B404 36, B607 17, B105 12. One low B405 is the generation-only ElementTree import. Scanner counts are triage leads, not 2,473 vulnerabilities.
- Main-tree compileall: succeeded with no diagnostics. `notupload/`: **22 malformed Python files** remain quarantined.
- Secret candidate scan: **74 candidates in 15 files** across 705 tracked/non-ignored files; no confirmed live credential after reviewed triage, but no proof of secret absence.

### Package and artifact verification

- Clean `out/audit_deploy`: 25 manifest files.
- Isolated invocation from that directory ended in `SELFTEST-OK`.
- The profile remained lab-only: hardware posture 3/7 HAVE, no FIPS provider, and lab TOFU warnings.
- `scripts/verify_reproducible_build.py` verified both DLL signatures/hashes, all four critical module hashes, and both SBOM signatures. The generated receipt was restored afterward to avoid test contamination.
- Despite the script title/output, this was **not** an independent rebuild and does **not** establish reproducibility or SLSA L2/L3.

SLSA 1.2 Build L2 requires signed provenance generated by a hosted build platform; L3 requires hardened builds that isolate runs and protect signing secrets from user-defined build steps. Local self-signed receipts do not meet those levels. [SLSA 1.2 Build Track](kimi-cite://web?url=https%3A%2F%2Fslsa.dev%2Fspec%2Fv1.2%2Fbuild-track-basics "citation")

### Secure-development assessment

The remediations follow the SSDF themes of protecting software from tampering, responding to vulnerabilities, and verifying third-party components, but the non-hermetic test suite, missing independent build provenance, and open review gaps prevent a mature SSDF conclusion. [NIST SP 800-218 SSDF](kimi-cite://web?url=https%3A%2F%2Fcsrc.nist.gov%2Fpubs%2Fsp%2F800%2F218%2Ffinal "citation")

---

## I. Quantified security scorecard

### Rubric

- **0–20:** absent or fundamentally broken controls; no credible evidence.
- **21–40:** major design/assurance failures; unsuitable beyond constrained experiments.
- **41–60:** useful controls but material architecture, verification, or operational gaps.
- **61–80:** generally sound implementation evidence with residual review/deployment gaps.
- **81–100:** mature independently reviewed engineering, broad target validation, strong operations; still not “perfect.”

Scores assess current evidence, not effort or feature count.

| Dimension | Score | Rationale |
|---|---:|---|
| Cryptographic correctness | **72** | Standard primitives, KAT/interop and extensive native tests; concrete AAD/state/counter fixes. Custom compositions, FFI secret copies, and absent independent cryptanalysis cap confidence. |
| Protocol/architecture security | **43** | Pairwise/native controls improved, but group membership/authorization is incomplete, delayed delivery is unsupported, and custom protocol review is absent. |
| Application security | **66** | Fail-closed gates, XML correction, package tests, bounded eviction, no medium/high Bandit findings. Non-hermetic tests and broken quarantined content remain. |
| Identity and access control | **52** | Signatures, enrollment, policy, and dual-officer components exist; group epoch/membership authorization and high-assurance identity/key-transparency composition remain unproven. |
| Data and metadata protection | **55** | AEAD, ratcheting, padding/chaff, and zeroization controls are present; FFI/GC copies, metadata/traffic-analysis validation, skipped-key behavior, and endpoint compromise limit assurance. |
| Dependency and supply-chain security | **70** | Hash-pinned runtime, clean Python/Rust advisory scans, signed artifact/SBOM checks. No independent rebuild, hosted provenance, or hardened build isolation. |
| Testing and verification maturity | **62** | 1,529 effective Python passes and 156 Rust passes with useful adversarial regressions. Sharded/non-hermetic evidence, skips, formatting debt, no executed Kani proof or live two-terminal run. |
| Operational readiness | **31** | Clean lab package works; production hardware posture, FIPS requirements, live operations, recovery, target-platform validation, and accreditation evidence are missing. |
| **Overall current security assurance** | **54** | Holistic judgement weighted toward exploitable architecture and deployment blockers; not an arithmetic average and not a certification. |

---

## J. Remediation roadmap and migration impacts

### P0 — release blockers

1. **Define and independently review the group security architecture.** Select MLS or another reviewed design; specify AS/DS, roster authorization, dual-officer policy, epoch ordering, joins/removals, recovery, and downgrade behavior. Prototype behind a new protocol identifier; do not mutate v2 semantics silently.
2. **Make tests hermetic and produce immutable-commit evidence.** Redirect every artifact/receipt/source write to isolated temporary locations. Run the complete suite twice from clean checkouts and publish exact commands, environment, failures, skips, and hashes.
3. **Implement and execute live two-terminal validation.** Include two real hosts, hostile network impairment, restart/rekey/concurrency, mixed-version refusal, state rollback, and recovery. Retain packet/test logs without secrets.
4. **Establish operational readiness.** Qualify hardware, attestation, validated crypto where required, enrollment without lab TOFU, backup/recovery, incident response, revocation, monitoring, and operator procedures.

### P1 — high-value assurance work

5. Commission independent cryptographic/protocol review and execute scoped formal verification; record assumptions and counterexamples rather than calling harnesses “proofs.”
6. Add bounded skipped-key retention or explicitly constrain transport semantics; test memory/CPU bounds and delayed delivery.
7. Move secret-consuming operations behind native APIs where practical; measure residual Python copies and memory dumps.
8. Establish hosted signed build provenance and independent reproducible rebuilds; protect signing keys offline/HSM and verify packaged file completeness continuously.
9. Run fuzzing, side-channel/fault-injection assessment, traffic-analysis evaluation, and target-platform/seL4 validation with documented scope.

### P2 — engineering hardening

10. Implement versioned PBKDF2 migration to benchmarked current parameters, considering Argon2id where policy permits. Preserve old verifier/decryption compatibility until successful migration; test interrupted and rollback cases.
11. Apply crate-wide formatting as a separate mechanical change and enforce it in CI.
12. Keep `notupload/` excluded from runtime/release paths; repair or remove it only through a separately reviewed cleanup.
13. Maintain dependency/advisory and secret-candidate scanning with reviewed suppressions and scheduled refresh.

### Migration register

| Change | Compatibility / operational impact | Safe transition |
|---|---|---|
| Group AAD v1 → v2 | Old frames intentionally fail; mixed peers cannot interoperate. | Versioned coordinated cutover; no ambiguous fallback; pre-cutover inventory and post-cutover rejection tests. |
| Future MLS/group redesign | New state, roster, delivery, recovery, and authorization semantics; possible loss of old delayed messages. | New protocol ID, parallel lab validation, explicit state export/rejoin policy, independently reviewed migration. |
| PBKDF2 210k → benchmarked current cost | Existing verifiers/backups depend on old cost; CPU/DoS latency changes. | Store algorithm/cost version, verify old then re-derive on successful authentication, benchmark, test interruption/rollback. |
| Hermetic test conversion | Tests depending on repository writes may fail and expose hidden order dependencies. | Fix fixtures rather than weakening assertions; compare clean repeated runs. |
| Native secret-lifetime redesign | FFI signatures and Python orchestration may change. | staged adapters, explicit ownership/lifetime contract, interop and dump analysis. |
| Hosted/reproducible release pipeline | Existing local receipts remain historical, not equivalent provenance. | Preserve old artifacts, generate new provenance, compare clean rebuild hashes, rotate/protect signing keys. |

---

## K. Final decisions and required evidence to reconsider

### Development/lab — CONDITIONAL GO

Allowed only with synthetic/non-sensitive data, isolated test networks, disposable keys, explicit lab mode, and operator acknowledgment that warnings are expected. The passing clean-package self-test supports this limited decision.

### Controlled external evaluation — CONDITIONAL GO

Allowed only for authorized security assessment with scope, logging, synthetic data, rate limits, rollback, and incident handling. Do not expose strategic-control functions to untrusted networks and do not represent the evaluation as an accreditation activity.

### Ordinary sensitive production — NO-GO now

Reconsider only after P0 items produce passing evidence and no unresolved high-severity finding remains. At minimum: hermetic clean full-suite runs, live two-terminal validation, independent protocol review, production host/identity readiness, and repeatable signed release evidence.

### Military/classified/strategic use — NO-GO

Reconsideration requires substantially more than green tests: independently reviewed protocols and implementations, qualified hardware and validated cryptographic modules where mandated, target-platform and side-channel assessment, hardened provenance/reproducibility, operational evaluation, incident/recovery exercises, and the formally responsible accreditation process. This report cannot grant an ATO or assert compliance.

---

## Auditor’s closing statement

The remediated tree is demonstrably safer in the specific areas tested. The most important improvement is not a larger algorithm list; it is stricter state-transition, context-binding, fail-closed, parser, packaging, and evidence discipline. The remaining gap is equally clear: a collection of strong primitives and successful tests is not yet a high-assurance communications system. Until the architectural and operational evidence catches up, deployment claims must remain narrower than the implementation’s ambitions.

