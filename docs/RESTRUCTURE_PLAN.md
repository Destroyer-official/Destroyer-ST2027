# RESTRUCTURE PLAN — Professional Military-Grade Project Layout
# Status: PROPOSAL for owner review. No files moved yet.

## 1. Why the current layout fails (evidence)

- 7032-line `tree.txt`: ~110 importable modules in ONE flat directory.
  Flat layout is explicitly discouraged by PyPA (name collisions, accidental
  shadowing, untestable packaging).
- PROVEN incident: repo directory `destroyer_core/` shadowed the installed
  wheel of the same name and broke the live two-terminal run; fixed by
  renaming to `rust_data_plane/`. Flat layout CAUSES this bug class.
- No defined cryptographic boundary (FIPS 140-3 / ISO/IEC 19790 requires an
  explicitly defined perimeter: services, algorithms, SSPs, self-tests,
  zeroisation inside; everything else outside).
- Mixed concerns per directory: tests beside crypto, planning docs beside
  keys, build artifacts beside sources (violates SSDF PS.1 — protect code
  from tampering — because review/audit cannot tell what is load-bearing).

## 2. Researched principles (sources)

- P1 PyPA packaging tutorial + glossary: single top-level import package
  named after the project, `src/` layout, `tests/` directory, `pyproject.toml`
  build backend, wheels+sdist published together.
- P2 Maturin project-layout guide: mixed Rust/Python via `rust/` +
  `src/<package>/` (their documented src-layout variant); distinct
  `module-name` (`destroyer_core._native` pattern) so IDEs/users never touch
  raw bindings.
- P3 NIST SP 800-218 SSDF v1.1 (PS/PW/RV): protect all code from tampering,
  secure defaults, evidence artifacts for every practice.
- P4 FIPS 140-3 IG + ISO/IEC 19790: cryptographic boundary explicitly defined;
  Security Policy distinguishes inside/outside (services, algorithms, SSPs,
  self-tests, zeroisation).
- P5 OpenSSF-style hygiene: `SECURITY.md`, signed releases, SBOM, no
  binaries beside sources without provenance files.

## 3. Proposed tree (complete)

```
secure-p2p/                         # repo root: packaging + policy only
├── README.md                       # mission, quick start, security posture
├── SECURITY.md                     # vulnerability reporting + supported versions
├── LICENSE                         # (to add — required for distribution)
├── pyproject.toml                  # maturin backend, single build entry +
│                                   # [project.scripts] secure-p2p entry point
├── requirements.txt                # pinned == with --hash (keep)
├── requirements-test.txt
├── pytest.ini
├── Cargo.toml                      # workspace root (members: rust/*)
├── Cargo.lock
├── src/
│   └── secure_p2p/                 # THE single import package (all 101 root modules land here)
│       ├── __init__.py             # public API surface (explicit re-exports only)
│       ├── app.py                  # SecureP2PChat orchestration (was secure_p2p.py core)
│       ├── cli.py                  # terminal entry (was secure_p2.py shim + ui/menus.py)
│       ├── config.py               # layered config loader (was config.py)
│       ├── models.py               # shared dataclasses (was data_models.py)
│       ├── dataplane.py            # Rust wrapper (was destroyer_node.py)
│       ├── observability.py        # logging setup (was logging_config.py + balanced_logging.py)
│       ├── crypto/                 # *** FIPS BOUNDARY: nothing outside imports inward ***
│       │   ├── __init__.py         # boundary API: KEM/sign/AEAD/KDF/wipe/self-test
│       │   ├── kem.py              # ML-KEM-1024 + McEliece + HQC (was pqc_algorithms KEM parts + liboqs_wrapper.py + triple_hybrid_kem.py)
│       │   ├── sig.py              # ML-DSA-87 + SLH-DSA (+ Falcon experimental) (was pqc_algorithms SIG parts)
│       │   ├── aead.py             # AES-256-GCM / ChaCha20-Poly1305 DEM (was SecureAESGCM + tls XChaCha block)
│       │   ├── kdf.py              # HKDF-SHA384/512, SHA3, PBKDF2 profiles (was KeySeparationManager + derivations)
│       │   ├── ratchet.py          # Double Ratchet (was double_ratchet.py)
│       │   ├── hybrid.py           # X3DH+PQ handshake (was hybrid_kex.py)
│       │   ├── zeromem.py          # wipers, erasers, mlock (was secure_memory_wiper.py + KeyEraser)
│       │   ├── entropy.py          # (was entropy_manager.py + quantum_rng.py)
│       │   ├── vault.py            # sealed key custody (was secure_key_manager.py + secure_key_provider.py + keys/*)
│       │   ├── rotation.py         # schedules + expiry (was forward_secrecy_manager.py + keys/rotation.py)
│       │   ├── sidechannel.py      # constant-time/timing guards (was side_channel_resistance.py)
│       │   └── selftest.py         # KATs + policy self-checks (was pqc self-tests + NISTTestVectorValidator)
│       ├── net/                    # transport, NO trust decisions
│       │   ├── framing.py          # length-prefix framing (was p2p_core FramedSocket)
│       │   ├── tcp.py              # dial/listen/accept, keepalives (was p2p_core SimpleP2PChat transport)
│       │   ├── tls.py              # mTLS 1.3 contexts (was tls_channel_manager.py)
│       │   ├── certs.py            # private CA + pin store (was ca_services.py + pq_certificate_authority.py)
│       │   ├── rendezvous.py       # 32B token (was inline CERT_READY block)
│       │   ├── heartbeat.py        # jittered heartbeats + chaff types
│       │   ├── protocol.py         # session state machine (was protocol_manager.py)
│       │   ├── peers.py            # peer book (was enhanced_peer_manager.py)
│       │   └── stealth.py          # silent-drop policy helpers + ops/firewall.md link
│       ├── identity/               # trust: who may talk
│       │   ├── pins.py             # TOFU safety numbers + pin store (was ui/safety_numbers.py)
│       │   ├── officers.py         # sealed officer credentials (was nc3 get_or_create part)
│       │   ├── devices.py          # (was multi_device_manager.py)
│       │   ├── ephemeral.py        # (was anonymous_identity_manager.py)
│       │   ├── peers.py            # alt: user/peer managers (was data/user_mgmt.py + data/peer_mgmt.py + data/manager.py)
│       │   └── zero_trust.py       # per-message verify + pins (was zero_trust_engine.py)
│       ├── nc3/                    # nuclear-release domain (isolated, audited separately)
│       │   ├── eam.py              # EmergencyActionMessage (was nc3_nuclear_command.py core)
│       │   ├── custody.py          # CriticalReleaseAuthority (was critical_release.py)
│       │   ├── pal.py              # war-key handling (no defaults, ever)
│       │   └── cli.py              # /nc3-send /nc3-verify /zeroize handlers (was inline in app.py)
│       ├── msg/                    # application traffic
│       │   ├── chat.py             # send/receive, history policy (CRITICAL excluded)
│       │   ├── files.py            # file pipeline (was file_transfer.py + secure_file_sharing.py + secure_file_transfer.py + data/file_transfer.py)
│       │   ├── codec.py            # framing codecs (was secure_message_serializer.py)
│       │   ├── outbox.py           # offline queue w/ backoff (was resilient_communication.py)
│       │   └── critical.py         # send_critical + gates (was inline in app.py)
│       ├── opsec/                  # operational security (all verified real, mostly opt-in)
│       │   ├── padding.py          # 1024B blocks (was operational_security.py padding engine)
│       │   ├── ephemeral.py        # TTL/read-once identities+messages (was operational_security rest + ephemeral_messaging.py)
│       │   ├── deniability.py      # containers/duress/dead-man (was anti_forensics.py; lab limits documented)
│       │   ├── anonymity.py        # Tor/jitter/cover/onion/mesh/DHT (was metadata_resistance.py + covert_channel_defense.py + network_adversary_resistance.py + decentralized_architecture.py)
│       │   └── airgap.py           # PSK/QR/offline cache (was air_gapped_operation.py)
│       ├── policy/                 # fail-closed engines (data, no I/O)
│       │   ├── nist_l5.py          # (was nist_level5_policy_engine.py)
│       │   ├── cnsa2.py            # (was cnsa2_policy_engine.py)
│       │   ├── agility.py          # (was cryptographic_agility.py, L3 removed)
│       │   ├── validation.py       # input validators (was InputValidator + security/validation.py)
│       │   └── errors.py           # security exception taxonomy (was cryptographic_errors.py)
│       ├── platform/               # OS/HW adaptation (all fallible, all explicit)
│       │   ├── hsm.py              # (was hsm_integration.py + platform_hsm_interface.py)
│       │   ├── enclave.py          # (was secure_enclave_key_storage.py + tee_manager.py)
│       │   ├── memory.py           # (was dep_impl.py + memory_protection_engine.py + enhanced_secure_memory.py + cross_platform_exception_handler.py)
│       │   ├── hardening.py        # (was maximum_security_hardening.py + security_hardening_manager.py + military_security_enforcement.py + enhanced_security_features.py)
│       │   ├── monitor.py          # (was threat_detection_engine.py + threat_detection_response_system.py + process_monitor_manager.py + continuous_security_monitor.py + security_status_monitor.py + security_recovery_manager.py + security_validation_orchestrator.py + security_validator.py + security_dependency_manager.py)
│       │   └── supply.py           # runtime dep verification (was dependency_security_verifier.py; SBOM side stays in tools/)
│       ├── persist/                # everything touching disk, audited as one surface
│       │   ├── profiles.py         # user profiles (sealed)
│       │   ├── queue.py            # unsent queue (memory-default, sealed opt-in)
│       │   ├── audit.py            # hash-chained log (was audit_logging_system.py + enhanced_audit_logging.py)
│       │   └── store.py            # generic sealed store (was storage.py)
│       └── ui/                     # terminal only, never handles key material
│           ├── menus.py · display.py · prompts.py · feedback.py (as-is)
├── rust/
│   └── destroyer_core/             # (moved as-is from rust_data_plane/)
│       ├── Cargo.toml · pyproject.toml · src/ · python/
├── tools/                          # operator/ceremony tooling (NOT imported by app)
│   ├── provision.py                # (was tactical_key_provisioner.py)
│   ├── ceremony.py                 # witnessed key ceremony (was scripts/witnessed_key_ceremony.py)
│   ├── pki.py                      # (was scripts/generate_sovereign_pki.py)
│   ├── cavp.py                      # (was scripts/cavp_algorithm_validator.py)
│   ├── repro.py                    # (was scripts/verify_reproducible_build.py)
│   ├── deploy.py                   # (was deploy_production.py)
│   ├── sbom.py                     # (was generate_production_sbom.py + supply_chain_security.py SBOM side)
│   ├── sign.py                     # (was sign_dependencies.py)
│   ├── verify.py                   # (was verify_deployment.py + verify_hardware_security.py)
│   └── bench.py                    # (was benchmark_military_crypto_suite.py)
├── ops/                            # runbooks + launch (NEW home for scattered ops files)
│   ├── firewall.md                 # (was docs/FIREWALL_IPV6.md)
│   ├── launch_alpha.bat · launch_bravo.bat (was launch_two_terminals.bat + start_*.bat, consolidated)
│   └── set_env.ps1 · set_env.sh    # (was set_env.bat/.sh)
├── tests/                          # ALL tests here (CI runs from root)
│   ├── test_remediated_63_findings.py · test_no_gap_military_audit.py
│   ├── test_nc3_nuclear_command_readiness.py · test_nc3_two_terminal_live_transfer.py
│   ├── test_production_grade_destroyer_suite.py · test_destroyer_core_production.py
│   ├── test_2027_defense_hardening.py · test_crypto_root_fixes.py
│   ├── test_cnsa_max_profile.py (from tests/) · test_no_emoji_property.py
│   ├── test_no_marketing_buzzwords_property.py · test_military_adversarial_suite.py
│   └── fixture_backends/           # run_two_terminals_*.py · master_military_battle_readiness_test.py
│                                   # run_full_potential_military_test.py · military_base_alpha/bravo.py
├── docs/                           # keep + extend: README/ARCHITECTURE/SOP/modules/ + this plan
├── config/                         # config.json + config_production.json + template + examples/
│                                   # (was root configs + enhanced_user_profile.json → examples/)
├── var/                            # ALL runtime state (NEW; path constants migrated here)
│   ├── log/                        # (was logs/)
│   └── lib/                        # keys/ certs/ credentials/ downloads/ unsent_messages/ compliance_reports/
├── third_party/
│   ├── oqs.dll[.sig/.hashes/.pub] · libsodium.dll[.sig/.hashes/.pub]
│   └── notupload/                  # pre-existing third-party archive (kept, never shipped)
├── archive/                        # keep as-is (history, never imported)
├── .github/workflows/defense_ci.yml # updated paths (tests/, rust/, tools/)
└── .venv/ .vscode/ .gitignore + tree snapshots → archive/ (env/editor, not product)
```

## 4. Mapping (old → new, EVERY file accounted)

App split: `secure_p2p.py` → `app.py` + `cli.py` + `msg/{chat,files,critical}.py`
+ `net/{framing,tcp,tls,rendezvous,heartbeat,protocol}.py` (mechanical split
by layer, zero logic edits in the move).
Crypto: `hybrid_kex.py`→`crypto/hybrid.py`; `double_ratchet.py`→`crypto/ratchet.py`;
`pqc_algorithms.py`→`crypto/{kem,sig,aead,kdf}.py` (+`sidechannel.py` parts);
`triple_hybrid_kem.py`→`crypto/kem.py` (fold); `liboqs_wrapper.py`→`crypto/_liboqs.py`;
`forward_secrecy_manager.py`→`crypto/rotation.py`; `quantum_rng.py`+
`entropy_manager.py`→`crypto/entropy.py`; `secure_memory_wiper.py`+`KeyEraser`
→`crypto/zeromem.py`; `secure_key_manager.py`+`secure_key_provider.py`+
`keys/*`→`crypto/vault.py`; `side_channel_resistance.py`→`crypto/sidechannel.py`.
Net: `p2p_core.py`→`net/{framing,tcp}.py`+cli parts; `tls_channel_manager.py`→
`net/tls.py`; `ca_services.py`+`pq_certificate_authority.py`→`net/certs.py`;
`protocol_manager.py`→`net/protocol.py`; `resilient_communication.py`→`msg/outbox.py`.
Identity: `anonymous_identity_manager.py`→`identity/ephemeral.py`;
`multi_device_manager.py`→`identity/devices.py`; `ui/safety_numbers.py`→
`identity/pins.py`; `zero_trust_engine.py`→`identity/zero_trust.py`;
`zk_authenticator.py`→`identity/zk.py` (gated); `threshold_cryptography.py`→
`identity/threshold.py` (gated); `data/user_mgmt.py`+`data/peer_mgmt.py`+
`data/manager.py`+`enhanced_peer_manager.py`→`identity/peers.py`.
NC3: `nc3_nuclear_command.py`→`nc3/{eam,pal}.py` (+officers→`identity/officers.py`);
`critical_release.py`→`nc3/custody.py`; EAM CLI blocks→`nc3/cli.py`.
Msg: `file_transfer.py`+`secure_file_sharing.py`+`secure_file_transfer.py`+
`data/file_transfer.py`→`msg/files.py`; `secure_message_serializer.py`→`msg/codec.py`;
`messaging/*`→`msg/` handlers folded into `chat.py`+`critical.py`.
OPSEC: `operational_security.py`→`opsec/{padding,ephemeral}.py`;
`ephemeral_messaging.py`→`opsec/ephemeral.py`; `anti_forensics.py`→`opsec/deniability.py`;
`metadata_resistance.py`+`covert_channel_defense.py`+
`network_adversary_resistance.py`+`decentralized_architecture.py`→`opsec/anonymity.py`;
`air_gapped_operation.py`→`opsec/airgap.py`.
Policy: `nist_level5_policy_engine.py`→`policy/nist_l5.py`;
`cnsa2_policy_engine.py`→`policy/cnsa2.py`; `cryptographic_agility.py`→
`policy/agility.py`; `cryptographic_errors.py`→`policy/errors.py`;
`data_models.py`→`models.py`; `base.py` retires with the mirrors.
Platform: `hsm_integration.py`+`platform_hsm_interface.py`→`platform/hsm.py`;
`secure_enclave_key_storage.py`+`tee_manager.py`→`platform/enclave.py`;
`dep_impl.py`+`memory_protection_engine.py`+`enhanced_secure_memory.py`+
`cross_platform_exception_handler.py`→`platform/memory.py`;
`maximum_security_hardening.py`+`security_hardening_manager.py`+
`military_security_enforcement.py`+`enhanced_security_features.py`→
`platform/hardening.py`; all `threat_*/process_monitor/continuous/security_*`
managers→`platform/monitor.py`; `dependency_security_verifier.py` runtime
half→`platform/supply.py`.
Persist: `storage.py`→`persist/store.py`; `audit_logging_system.py`+
`enhanced_audit_logging.py`→`persist/audit.py`; unsent-queue logic→`persist/queue.py`;
user profiles→`persist/profiles.py`.
UI: `ui/*` moves as-is. Misc app: `destroyer_node.py`→`dataplane.py`;
`config.py`→`config.py`; `logging_config.py`+`balanced_logging.py`→`observability.py`.
Tools/tests/ops/var/third_party per §3 tree. `core/ crypto/ data/ keys/
messaging/ network/ security/ ui/ utils/` + `secure_p2p_core/` mirrors →
DELETED after merge (parity tests decide; root orphans already archived).
`redesign/` skeleton deletes itself on approval. `tree.txt` → `archive/`.
Sibling `p2p_staging*` folders are OUTSIDE the repo — untouched by this plan.

## 5. Migration phases (each ends green or rolls back)

- P0 Freeze: tag commit, full battery record (25+15+9+6+live runs).
- P1 Skeleton + import shims: create tree, move files with `git mv`, leave
  backward-compat shims at old paths re-exporting (1 release).
- P2 Split `secure_p2p.py` by layer (mechanical moves only, no logic edits).
- P3 Merge mirrors, delete duplicates (parity tests decide).
- P4 CI paths, docs paths, SBOM regenerate; full battery + live two-terminal
  both modes; shims removed next release.
- P5 FIPS boundary audit: `crypto/` gets OWN selftest + policy file.

## 6. Naming rules (enforced in review)

`snake_case` modules, one concern per module, `<domain>_<thing>.py` only when
a package would hold one file; no `*_test` outside `tests/`; no binaries
beside sources without `.sig/.hashes/.pub`; no `utils.py` grab-bags
(split into named helpers); ENVIRONMENT flags documented in one table
(`docs/SOP.md` §2 + `config/` schema).
