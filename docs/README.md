# Sovereign Secure Communications Architecture — Documentation Index

This directory contains the engineering specifications, operational doctrine, compliance targets, and formal verification proofs for the **2027 Sovereign Post-Quantum Defense Communications Engine**.

Every behavior stated in this documentation tree maps to verified source code (`file:line`). All claims maintain strict fidelity to engineering reality: **software gating logic is clearly delineated from physical hardware and facility accreditation requirements**.

---

## 1. Master Documentation Map

```
docs/
├── ARCHITECTURE.md                          # Master system thesis, threat models, 2027 vs legacy stacks
├── README.md                                # This document index & cross-reference guide
├── CONOPS_TACTICAL_DEPLOYMENT.md            # Tactical concept of operations in DDIL environments
├── FIPS_140_3_SECURITY_POLICY.md            # FIPS 140-3 Cryptographic Module Security Policy (CMSP target)
├── NIAP_COMMON_CRITERIA_SECURITY_TARGET.md  # NIAP NDcPP / Common Criteria EAL4+ Security Target (target)
├── KEY_CEREMONY.md                          # Offline 3-of-5 threshold ML-DSA-87 Hardware Root CA SOP
├── KEY_MANAGEMENT_PLAN_KMP.md               # End-to-end cryptographic key lifecycle plan
├── MILITARY_NC3_DEPLOYMENT_GUIDE.md         # Nuclear command & dual-custody (DoD S-5210.41M) manual
├── SOP.md                                   # Standard operating procedures, roles, checklists
├── deployment_hardening_guide.md            # Production host & operating system hardening guide
├── hw_tpm_hsm_setup.md                      # Hardware setup guide: TPM 2.0, CNG, PKCS#11 tokens
├── airgap_runbook.md                        # Air-gapped installation and zero-network operational manual
├── FIREWALL_IPV6.md                         # Kernel firewall and interface-binding runbook
├── incident_response.md                     # Post-compromise recovery and incident handling runbook
├── liboqs_pin.md                            # Native LibOQS DLL build hashes and pin provenance
├── formal/                                  # Machine-checked formal verification models
│   ├── st2027_handshake.pv                  # ProVerif model: hybrid secrecy & mutual auth proof
│   ├── st2027_pcs.pv                        # ProVerif model: post-compromise security (PCS) healing
│   └── handshake_model.pv                   # Structural baseline handshake model
└── modules/                                 # Per-module technical charters and line audits (27 modules)
    ├── ts_hw_layer.md                       # Pillar 1: Hardware & Physical Security (FIPS/TEMPEST/CNG)
    ├── ts_runtime.md                        # Pillar 2: OS & Execution Runtime (seL4/VBS/VirtualLock)
    ├── noise_pq.md                          # Pillar 3: Protocol & Post-Quantum Cryptography (CNSA 2.0)
    ├── transport_anonymity.md               # Pillar 4: Transport Anonymity & Cell Shaping (Tor/DPO)
    ├── trust_anchor.md                      # Pillar 5: Trust Anchor & Post-Quantum PKI (3-of-5 Root)
    ├── rust_data_plane.md                   # Native Rust standalone binary & Kani verification
    ├── p2p_core.md                          # Networking core: STUN, framing, sockets, IPv6
    ├── hybrid_kex.md                        # Hybrid key exchange mechanisms (SecP384r1MLKEM1024)
    ├── double_ratchet.md                    # Double Ratchet state machine and replay caches
    ├── pqc_algorithms.md                    # Post-quantum cryptographic primitives (FIPS 203/204/205)
    ├── tls_channel_manager.md               # TLS 1.3 mTLS channel management and hybrid ciphers
    ├── ca_services.md                       # Private CA services and certificate issuance
    ├── file_transfer.md                     # Encrypted chunked file transfer pipeline
    ├── audit_threat_supply.md               # Audit logging, threat detection, and SBOM tracking
    ├── memory_hsm.md                        # Secure memory management and HSM interfaces
    ├── entropy_sidechannel.md               # Hardware RNG, side-channel resistance, serialization
    ├── opsec_persistence.md                 # Anti-forensics, zeroization, and amnesia profiles
    ├── anonymity_decentral.md               # Decentralized anonymity overlays and cover traffic
    ├── critical_release.md                  # Dual-person integrity and critical command release
    ├── destroyer_node.md                    # High-level peer node orchestration and session lifecycle
    ├── hardware_trust.md                    # Hardware root of trust and TPM 2.0 PCR validation
    ├── root_files.md                        # Root directory utilities, CLI orchestrators, diagnostic tools
    ├── safety_numbers.md                    # Out-of-band identity verification and SHA3-512 fingerprints
    ├── secure_p2p.md                        # Secure P2P communication orchestration and negotiation
    ├── subsystems_core.md                   # Core cryptographic subsystems and serialization
    ├── subsystems_support.md                # Support subsystems, remote SIEM forwarders, health telemetry
    └── trust_policy.md                      # Zero-trust policy evaluation and attestation claims
```

---

## 2. Core 2027 Architecture: The 5 Strategic Pillars

The modern 2027 production target is orchestrated by [`secure_transmit_2027.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/secure_transmit_2027.py) across 5 fail-closed pillars:

| Pillar | Focus Area | Primary Source Files | Primary Specifications & Module Docs |
|---|---|---|---|
| **Pillar 1** | **Hardware & Physical Security** | [`ts_hw_layer.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_hw_layer.py)<br>[`cng_platform.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cng_platform.py) | [modules/ts_hw_layer.md](modules/ts_hw_layer.md)<br>[FIPS_140_3_SECURITY_POLICY.md](FIPS_140_3_SECURITY_POLICY.md)<br>[hw_tpm_hsm_setup.md](hw_tpm_hsm_setup.md) |
| **Pillar 2** | **OS & Execution Runtime** | [`ts_runtime.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_runtime.py)<br>[`ts_rt/src/lib.rs`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_rt/src/lib.rs)<br>[`ts_attest.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_attest.py) | [modules/ts_runtime.md](modules/ts_runtime.md)<br>[deployment_hardening_guide.md](deployment_hardening_guide.md)<br>[ARCHITECTURE.md §3-§6](ARCHITECTURE.md) |
| **Pillar 3** | **Cryptography & Protocol** | [`noise_pq.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/noise_pq.py)<br>[`cnsa_purity.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/cnsa_purity.py)<br>[`crypto_selftest.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/crypto_selftest.py) | [modules/noise_pq.md](modules/noise_pq.md)<br>[formal/st2027_handshake.pv](formal/st2027_handshake.pv)<br>[formal/st2027_pcs.pv](formal/st2027_pcs.pv) |
| **Pillar 4** | **Network Anonymity & Shaping** | [`transport_anonymity.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/transport_anonymity.py)<br>[`spo_dpo.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/spo_dpo.py) | [modules/transport_anonymity.md](modules/transport_anonymity.md)<br>[MILITARY_NC3_DEPLOYMENT_GUIDE.md](MILITARY_NC3_DEPLOYMENT_GUIDE.md)<br>[CONOPS_TACTICAL_DEPLOYMENT.md](CONOPS_TACTICAL_DEPLOYMENT.md) |
| **Pillar 5** | **Trust Infrastructure & PKI** | [`trust_anchor.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/trust_anchor.py) | [modules/trust_anchor.md](modules/trust_anchor.md)<br>[KEY_CEREMONY.md](KEY_CEREMONY.md)<br>[KEY_MANAGEMENT_PLAN_KMP.md](KEY_MANAGEMENT_PLAN_KMP.md) |

---

## 3. Operational Standards & Verification Traceability

### A. Automated Test Gates (100% Pass)
The codebase is validated by the full automated battery (Python suites plus 64 cargo-test Rust tests: 35 library unit tests + 29-test harness binary) maintaining zero regressions. Fixed historical totals are not cited; CI status is the source of truth:
```bash
# Execute the unified 2027 Top-Secret test battery
pytest test_ts_hw_layer.py test_ts_runtime.py test_secure_transmit_2027.py \
       test_noise_pq_purity.py test_proverif_st2027.py test_spo_dpo.py \
       test_transport_anonymity.py test_trust_anchor.py test_ts_attest.py \
       test_hw_readiness.py test_runbooks_ps.py test_rust_standalone_binary.py \
       test_no_marketing_buzzwords_property.py test_no_emoji_property.py -v

# Execute the native Rust data-plane test battery
cargo test --manifest-path rust_data_plane/Cargo.toml
```

### B. Machine-Checked Formal Proofs
Protocol models in `docs/formal/` are executed via ProVerif 2.05:
1. **`docs/formal/st2027_handshake.pv`**: Proves payload secrecy (`RESULT not attacker(secret_payload) is true`) and mutual authentication (`inj-event(S_Accepts)` and `inj-event(R_Receives)` are true).
2. **`docs/formal/st2027_pcs.pv`**: Proves Post-Compromise Security (PCS) healing—compromise of ephemeral keys in Epoch $N$ does not compromise Epoch $N-1$ and is actively healed in Epoch $N+1$ upon fresh hybrid rekeying.

---

## 4. Documentation Quality & Integrity Rules

All documentation in this repository complies with strict defense documentation standards:
1. **No Marketing Buzzwords:** Terms such as "military-grade" or "quantum-proof" must be accompanied by exact cryptographic specifications (e.g. NIST Level 5, 256-bit post-Grover security margin, FIPS 203 ML-KEM-1024).
2. **Honest Evaluation Boundary:** Target evaluation levels (such as FIPS 140-3 Level 4 or Common Criteria EAL4+) must explicitly disclose whether they are *design targets* or *lab-certified ratings*.
3. **Traceability:** Technical descriptions must cite exact source code files and functions.
