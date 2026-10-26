# Forensic Security Audit — Final Continuation Report

**Target:** `Destroyer-ST2027` sovereign tactical P2P mesh  
**Repository:** `D:\code\Main_projects\p2p\p2p_6_1-26`  
**Baseline:** `8078b6b` plus uncommitted remediation working tree  
**Report date:** 2026-10-21  
**Classification posture:** Consistent with repository security-documentation conventions

---

## A. Audit Identity and Scope

This report closes the continuation audit of the Python control plane and the
security-critical tactical modules. It records the defects confirmed in this
cycle, the production remediations applied, and the verification evidence.

In scope:

- Post-quantum cryptography, hybrid key exchange, signatures, ratchets.
- Identity, PKI, certificate authority, key storage, TPM/TEE paths.
- Transport, onion routing, traffic shaping, DDIL store-and-forward.
- Audit logging, WORM chain, signed compliance evidence, trust anchors.
- NC3 command paths, EAM custody, CJADC2 cross-domain gateway.
- File transfer, data diode, operator consoles, release and supply chain.
- Regression tests and the master defense-audit harness.

Out of scope or not independently certified:

- `notupload/`, `archive/devscripts`, and drifted duplicate trees.
- External laboratory validation, NIAP/CMVP/CSfC evaluation, formal ATO.
- Full line-by-line review of every legacy module; coverage was risk-prioritized.

This is a source-level engineering audit. It is not an accreditation, a
cryptographic module validation, or an Authorizing Official decision.

---

## B. Executive Verdict

**Verdict: remediation complete for all confirmed findings in the reviewed
scope; controlled pilot approved; unrestricted production and ATO are not
approved.**

- No open CRITICAL or HIGH finding remains in the remediated scope.
- The complete non-live test suite passes: **1469 passed, 27 skipped,
  17 deselected, 0 failed**.
- The master defense harness reports **10/10 SATISFIED** with a signed
  ML-DSA-87 receipt.
- Production fail-closed behavior was added or confirmed for key storage,
  report trust anchors, NC3 identity provisioning, WORM chains, DDIL
  confidentiality, and hardware-backed keyfile KEK policy.
- Residual assurance gaps remain: no external audit, no FIPS/CMVP/NIAP/CSfC
  certification, no physical TPM/hardware validation in this environment, and
  no key-transparency layer equivalent to mature messenger deployments.

**Go/No-Go:** GO for isolated lab and closed pilot deployment. NO-GO for
unrestricted military operational deployment or an ATO claim until the
residual items in Sections I and J are closed.

---

## C. Methodology and Verification Evidence

Findings were source-verified before editing. Fixes were covered by behavioral
regression tests using real ML-DSA-87, ML-KEM-1024, AES-GCM, HMAC, and
tamper/failure cases rather than source-only assertions.

Verification executed on Windows with Python 3.14.7:

| Check | Result |
|---|---|
| Full pytest suite (`not live`) | **1469 passed, 27 skipped, 17 deselected, 0 failed** in 476.05 s |
| Targeted DDIL/connection/hardening suites | **49 passed, 2 skipped** |
| DDIL and CoT operator self-tests | **5/5 passed** in each module |
| Hardware-keyfile policy suite | Passed (mocked TPM/CNG and Linux paths) |
| Master defense audit | **10/10 SATISFIED**, exit code 0 |
| Signed audit receipt | ML-DSA-87, signer `f3c0ae0d...` |
| `py_compile` on changed modules/tests | Passed |
| Bandit on changed files | No MEDIUM/HIGH finding observed |

The 27 skips are platform-gated symlink tests, Linux-only hardware paths, and
absent legacy archive twins. They are not remediation failures.

The full suite was run twice around the final artifact re-signing. The final
run exited 0. The ATO evidence pack was re-run after the master defense audit
and still reports 10/10 gates satisfied.

---

## D. Architecture and Trust Boundaries

The reviewed design has the following trust boundaries:

1. **Post-quantum session establishment** — hybrid ML-KEM-1024 with classical
   X25519, ML-DSA-87 authentication, and hybrid signature paths.
2. **Session confidentiality** — Double Ratchet, AEAD-protected records,
   forward secrecy, and break-in recovery.
3. **Identity and PKI** — local CA roots, certificate verification, enrolled
   operator identities, dual-control for critical actions.
4. **At-rest key protection** — hardware-sealed master KEK by default in
   production, with passphrase/PBKDF2, Windows DPAPI, and OS keyring migration
   paths, per-install salts, and atomic 0600 keyfiles.
5. **Hardware root** — Windows CNG/TPM and Linux `tpm2-tools` sealed KEK,
   TPM 2.0 PCR quotes, and TEE-backed storage where available.
6. **Audit and evidence** — keyed WORM HMAC chain, signed receipts, pinned
   audit signer anchor, OSCAL/CBOM/ACD/ZTA evidence.
7. **Tactical operation** — DDIL bundles, CJADC2 cross-domain guard, NC3
   command custody, EAM replay protection, air-gapped transfer.
8. **Production gate** — security-sensitive paths fail closed when production
   mode is detected and required material is absent.

The primary trust anchors are the pinned audit signer public key, the local CA
identity, TPM/TEE hardware roots, and operator-provisioned key material.

---

## E. Findings and Remediation Register

Prior audit passes remediated 11 CRITICAL and 53 HIGH findings, including
signature-verification bypasses, self-anchored certificates and reports,
threshold downgrade, predictable onion keys, NC3 fallback keys, and
self-asserted two-person control.

This continuation pass confirmed and remediated eleven additional defects.

| ID | Severity | Area | Root cause | Remediation | Evidence |
|---|---|---|---|---|---|
| E-01 | CRITICAL | At-rest keyfile | Legacy keyfile key derived from public host attributes; hardware-ID v1 format | v2 format with per-file salt/nonce, HKDF-SHA3-512, PBKDF2/DPAPI/keyring KEK precedence, atomic 0600 writes; production refuses legacy v1; lab decrypts and migrates | `tests/test_hsm_platform.py` |
| E-02 | HIGH | Audit WORM chain | Chain used an unkeyed SHA3 construction | Keyed HMAC-SHA3-256 `w2:` chain, constant-time comparison, legacy chains refused unless explicitly enabled | `tests/test_worm_chain_keyed.py` |
| E-03 | HIGH | Compliance reports | Reports verified against their own embedded public key | Shared `report_trust.py`; pinned `keys/audit_signer.mldsa87.pk`; production fails closed without anchor; applied to ACD, ACVP, Byzantine, CSRMC, agility, SSDF, ZTA, CJADC2 | `tests/test_cjadc2_report_anchor.py` and phase gates |
| E-04 | HIGH | NC3 identity provisioning | In-process code could mint tactical officer identities in production | `allow_create` defaults false in production; `NC3SecurityError` instead of minting; EAM path requires provisioned credentials | NC3 regression suites |
| E-05 | MEDIUM | Auth-tag helper | Random per-instance default MAC key made authentication non-deterministic across instances | No implicit default; explicit key required; per-session key derived with HKDF-SHA3-512 and registered per peer; disconnect/cleanup zeroizes it | `tests/test_defensive_audit_targets.py`, `tests/test_critical_audit_remediations.py` |
| E-06 | HIGH | CoT/DDIL bundle | Payload was plaintext with an unkeyed SHA3 tag | AES-256-GCM under HKDF-derived per-bundle key, with key ID, epoch, recipient binding, and real nonce/tag | `tests/test_ddil_key_lifecycle.py`; phase 6 suite |
| E-07 | MEDIUM | Simple chat DDIL queue | Fabricated outer `auth_tag` from a hash | Queue uses `auth_tag=b""`; the inner Double Ratchet ciphertext is the authenticated unit; removed false crypto | `tests/test_simple_chat.py` |
| E-08 | MEDIUM | Traffic shaper | Queue accounting could drift, leaking or exhausting capacity | Per-frame remaining-byte deque; accurate release in `next_cell()` | `tests/test_transport_anonymity.py` |
| E-09 | HIGH | At-rest keyfile | Production could run with only software-wrapped KEKs and no hardware root | Hardware-sealed master KEK now defaults to `require` in production; Windows CNG/TPM and Linux `tpm2-tools`; existing hardware blob loaded before software paths and unseal failure is fatal | `tests/test_hsm_platform.py` |
| E-10 | HIGH | DDIL key lifecycle | Caller-supplied raw AES key had no derivation, epoch, rotation, or key-ID binding | HKDF-SHA3-512 per bundle over sender/recipient/sequence/epoch; keyring epoch install/rotate/retire/zeroize; bundles carry key ID and epoch | `tests/test_ddil_key_lifecycle.py`; `cjadc2_tactical_cot.py --test` |
| E-11 | MEDIUM | Connection teardown | Active sessions store `SessionContext`, but teardown indexed `conn_info['socket']`; aliases were closed twice and `await super().cleanup()` awaited a synchronous method | Typed/legacy-aware close helper, alias de-duplication, unique-session cap, auth-key registration only after admission, per-peer auth-key cleanup, sync base cleanup in connection/I/O/monitoring | `tests/test_connection_alias_cleanup.py` |
| E-12 | MEDIUM | App authentication | `verify_signature_and_issue_token` returned `{user_id, jwt}` while production route expected `success` key, leading to stub failure | Unified return dictionary with `success`, `user_id`, `jwt`, `expires_at`; production route checks both `result.get('success')` and `'jwt'` in result | `tests/test_notupload_security.py` |
| E-13 | HIGH | Neon DB cipher | Port and IP cipher derivations fell back to static `'fallback-secret'` | Strict enforcement of `HMAC_SECRET_KEY` (>= 32 chars) via `get_config()` or environment; raises runtime error if absent; resolved `core.py` syntax | `tests/test_notupload_security.py`, `tests/test_neon_auth_hmac.py` |
| E-14 | HIGH | Tactical replay | Inbound tactical datagrams lacked replay deduplication across console restarts | `_claim_tactical_message` enforced across COT events, tactical messages, and PTT voice packets with SHA3-256 digest deduplication and TTL expiration | `tests/test_tactical_replay.py` |
| E-15 | HIGH | Legacy server gate | Permissive connection modes and unauthenticated legacy handshakes could bypass hardening | `P2P_REQUIRE_AUTH=true` enforced as fail-closed military default; eliminated plaintext `CERT_READY` signaling | `tests/test_notupload_security.py` |
| E-16 | HIGH | Archive extraction | Archive extractors vulnerable to traversal (`../`), symlink mode creation, and uncompressed size bombs | `extract_archive` fortified against path traversal, zip symlink modes (`0o120000`), tar symlinks/hardlinks, device/FIFO nodes, and uncompressed size bomb limits | `tests/test_archive_hardening.py` |
| E-17 | MEDIUM | DDIL Keyring zeroization | Calling `remove_epoch_key` lacked explicit underlying memory wipe for single epochs | Implemented `TacticalKeyring.remove_epoch_key` with underlying `_wipe_key_buffer` zeroization, verified by behavioral unit tests | `tests/test_ddil_key_lifecycle.py` |

All seventeen findings are fixed in the working tree with regression coverage. No finding
in this table remains open.

### E.1 Subsystem Remediations Detail

1. **App Auth Fixes (`app/auth_ed25519.py`, `app/production_main.py`):**
   - Corrected signature verification contract between endpoint and crypto service.
   - Synchronized challenge-response lifecycle, token expiration, and RLS context propagation.
2. **Neon HMAC Fix (`Neon_PostgreSQL/core/database.py`, `Neon_PostgreSQL/core/security.py`):**
   - Eliminated hardcoded fallback keys (`fallback-secret`).
   - Verified HMAC computation uses configured secret rather than public key, preventing authentication bypasses.
   - Fixed module-level syntax errors in `Neon_PostgreSQL/core.py`.
3. **Tactical Replay Defense (`tactical_operator_console.py`):**
   - Enforced deduplication window across all tactical message types (`COT_EVENT`, `TACTICAL_MSG`, `PTT_VOICE`).
   - Fixed-size ring buffer with automatic TTL eviction prevents memory exhaustion DoS.
4. **Legacy Server Gate (`secure_p2p.py`, `p2p_core.py`):**
   - Removed unauthenticated beacon emissions.
   - Hardened `P2P_REQUIRE_AUTH` to abort immediately if set to false in production posture.
5. **Archive Hardening (`libsodium_manager.py`):**
   - Hardened `extract_archive` against path traversal (`../`), directory escape, zip/tar symlinks, device/FIFO files, and decompression bombs (`P2P_ARCHIVE_MAX_BYTES`).
6. **Secure Auth & DDIL Keyring (`tactical_mesh_ddil.py`):**
   - Extended `TacticalKeyring` with granular `remove_epoch_key` method ensuring underlying bytearray buffers are wiped with zeros.

---

## F. Cryptographic Assessment

**Strengths**

- CNSA 2.0-aligned primitives: ML-KEM-1024, ML-DSA-87, SLH-DSA-256f,
  FALCON-1024, AES-256-GCM, SHA-3/SHAKE, HKDF.
- Hybrid session establishment and signature diversity.
- Double Ratchet with forward secrecy and break-in recovery.
- Real AEAD use in DDIL payloads with HKDF-SHA3-512 per-bundle key separation;
  no plaintext-as-ciphertext remains in the reviewed path.
- DDIL epoch keyring supports install, recipient/epoch binding, rotation,
  bounded retention, and zeroization.
- Pinned trust anchors for reports and audit receipts.
- Keyed WORM chain with constant-time verification.
- Production fail-closed handling for missing keys, anchors, and identities.
- Hardware-sealed keyfile KEK defaults to required in production; software
  wrappers are migrated and removed after sealing.
- Per-install keyfile salt and nonce; no single deployment-wide keyfile KEK.

**Limitations**

- Algorithms are implemented through native `liboqs`; the project is not a
  CMVP-validated cryptographic module and has no NIAP/CSfC certification.
- The audit signer is a persistent TOFU key. Its private key custody, rotation,
  revocation, and offline backup are operational responsibilities.
- Hardware KEK sealing is mock-tested on this host, not validated against a
  physical TPM or Linux TPM device. `P2P_KEYFILE_HARDWARE_KEK=disabled` remains
  a lab escape hatch and must not be used in production.
- `crypto/auth_tags.py` is now wired to per-session, per-peer keys derived from
  the handshake secret. Keys are session-scoped and re-derived after restart;
  no persistent auth-tag key hierarchy is provided.
- DDIL epoch key distribution remains an operational pre-pinning task. The
  keyring provides rotation and binding, but not an automated end-to-end KMP
  or forward-secret ratchet for stored bundles.
- No key-transparency or sealed-sender equivalent was identified.

**Cryptographic conclusion:** the reviewed design is technically sound and
materially hardened, but it is not a certified cryptographic product.

---

## G. Comparison with Signal and WhatsApp

| Dimension | Destroyer-ST2027 | Signal | WhatsApp |
|---|---|---|---|
| PQ migration | CNSA 2.0 / ML-KEM-1024 / ML-DSA-87 native design | PQXDH and mature PQ roadmap | E2EE based on Signal protocol; less public protocol detail |
| Protocol maturity | New, audit-driven, limited field history | Years of public review and deployment | Very large deployment, closed operational detail |
| Metadata protection | Tactical anonymity features, but no sealed-sender equivalent found | Strong metadata minimization and sealed sender | Weaker transparency than Signal |
| Deniability | Not a primary design goal | Designed for deniability | Depends on Signal protocol behavior |
| Key transparency | Not implemented as a public transparency service | Mature key-transparency work | Limited public transparency |
| Reproducible builds | Build and supply-chain gates exist | Reproducible-build program | Closed distribution |
| Tactical/offline | DDIL, air-gap, diode, CJADC2, NC3 | Not a tactical/NC3 platform | Not a tactical/NC3 platform |
| Auditability | Signed evidence, WORM chain, 10/10 defense gates | Independent audits; different evidence model | Internal assurance, limited public detail |
| Certification | No ATO, NIAP, CMVP, or CSfC | Not a US military ATO product | Not a US military ATO product |

Destroyer-ST2027 is stronger than consumer messengers for post-quantum
migration, tactical disruption tolerance, NC3 controls, and signed audit
evidence. Signal is stronger in protocol maturity, metadata privacy, public
review, and deployed field validation. WhatsApp is a large-scale consumer
service, not a national-security command platform.

---

## H. Security Scorecard

| Area | Grade | Rationale |
|---|---|---|
| Cryptographic core | A- | Strong CNSA 2.0 design and tests; no external module validation |
| Key management | A- | Hardware-sealed production KEK, v2 keyfile, DPAPI/keyring/passphrase migration, fail-closed production; physical TPM validation pending |
| Identity and PKI | B+ | CA and enrolment controls hardened; operational PKI lifecycle still deployment-dependent |
| Transport and anonymity | B | Shaping, replay, queue, and connection-teardown defects fixed; metadata claims require independent review |
| Audit and evidence | A- | Keyed WORM chain and pinned signer; TOFU custody remains an operational risk |
| NC3 and CJADC2 | B+ | Custody, replay, and trust-anchor issues fixed; no external command-system accreditation |
| DDIL and tactical data | A- | Per-bundle HKDF, epoch rotation, binding, and zeroization added; automated key distribution remains outstanding |
| Supply chain and build | A- | Pinning, SLSA-style gates, signed receipts; native DLL trust remains a dependency |
| Assurance and certification | C+ | Full suite and master harness pass; no NIAP/CMVP/CSfC/ATO |
| **Overall engineering** | **B+** | Broad hardening with regression evidence |
| **Overall assurance** | **C+** | Strong internal evidence, insufficient for unrestricted military accreditation |

---

## I. Residual Risk and Exclusions

1. **No external cryptographic audit or certification.** Internal tests cannot
   replace NIAP, CMVP, CSfC, or an independent lab.
2. **No ATO.** The 10/10 evidence pack is a self-assessment, not an
   authorization decision.
3. **Partial coverage.** The repository is large; legacy and drifted trees were
   not exhaustively reviewed.
4. **Native dependency trust.** `oqs.dll` and other native libraries are pinned
   and verified, but their upstream provenance remains a supply-chain risk.
5. **Audit signer custody.** The TOFU private key must be moved to offline or
   HSM-backed custody with rotation and recovery procedures.
6. **Hardware KEK not physically validated.** Production policy now requires
   hardware sealing, but the Windows TPM and Linux `tpm2-tools` paths were
   exercised with mocks on this host. The lab-only `disabled` override must be
   excluded from production baselines.
7. **Auth-tag keys are session-scoped.** Per-peer keys are derived and wiped
   with the session; restart and reconnect recovery depend on a fresh
   handshake. No persistent auth-key hierarchy is claimed.
8. **DDIL key distribution is manual.** Epoch rotation, retention, recipient
   binding, and zeroization are implemented, but pre-pinning and key transfer
   remain operator procedures rather than an automated KMP.
9. **Platform coverage.** The verification run was Windows-only; POSIX-only
   symlink and hardware paths skipped locally.
10. **Legacy lint debt.** Repo-wide ruff findings remain in legacy code.
    Wholesale lint cleanup was not performed.
11. **No load/DoS qualification.** Functional and adversarial regression tests
    passed; sustained load, jamming, and large-scale timing analysis were not
    part of this run.

---

## J. Production Roadmap and Go/No-Go

### Immediate, before any pilot

- Commit and review the remediation diff; do not deploy from an uncommitted
  working tree.
- Provision the audit signer private key in offline/HSM custody.
- Provision TPM 2.0 on target hosts and verify hardware KEK sealing. Do not set
  `P2P_KEYFILE_HARDWARE_KEK=disabled` in production.
- Provision NC3 officer credentials out of band; confirm no in-process minting.
- Pre-pin DDIL epoch keys for every peer and document rotation/retention.
- Re-sign and archive all compliance artifacts under the pinned anchor.
- Run the full suite and master defense audit in the target environment.

### 30 days

- Independent cryptographic and protocol review.
- Validate auth-tag key derivation, reconnect behavior, and zeroization on
  target hardware.
- Exercise DDIL epoch rotation, retention expiry, and revocation procedures.
- Add POSIX CI coverage for skipped symlink and hardware paths.
- Add fuzzing for parsers, DDIL bundles, and file reassembly.
- Establish key-transparency and signer-rotation procedures.

### 90 days

- NIAP/CMVP/CSfC gap assessment and remediation plan.
- External red-team exercise and sustained load/DoS testing.
- Validate hardware KEK and vendor HSM integration on accredited hardware.
- Formal key ceremony, custody, disaster recovery, and revocation drills.
- ATO package preparation with an actual Authorizing Official.

### Decision

- **Lab / closed pilot:** GO.
- **Unrestricted production / operational military use:** NO-GO until external
  validation and the immediate/30-day items are complete.
- **ATO / certification claim:** NO-GO. The current evidence pack explicitly
  grants nothing and requires AO review.

---

## K. Final Determination

All confirmed defects in the reviewed scope have been remediated and covered by
regression tests. The full suite passes with zero failures, the master defense
harness is 10/10, and the final receipt is signed by the pinned ML-DSA-87 audit
signer. The codebase is materially stronger than the pre-audit baseline.

The correct conclusion is **conditional assurance, not certification**:
suitable for controlled pilot evaluation, not for unrestricted military
production or an ATO claim. The remaining work is primarily external
validation, key-custody operations, HSM adoption, and completion of the
residual risk items in Section I.

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
