# Phase 3 - Prohibited Terminology Inventory

This register catalogs all occurrences of prohibited promotional, sensational, and overclaiming terms across all tracked files (`git ls-files`).

Categories:
- **(a) Promotional / Overclaiming Phrase:** Marketing assertion, decorative text, or unverified capability claim. Must be removed or replaced per the replacement table.
- **(b) Standard Title / Identifier (KEEP):** Exact published standard or specification title/number (e.g. FIPS 140-3, NSA CNSA 2.0, NATO SDIP-27, DoD 5220.22-M). Kept verbatim with exact citation.
- **(c) Identifier / File Name:** Code symbol, variable, function name, class, config key, CLI flag, or file path. Handled in Stage B with dependency updating and test verification.

**Total Findings:** 2575

| Location | Term | Context | Category | Action |
|---|---|---|---|---|
| `.github/workflows/defense_ci.yml:31` | `zero-trust` | `- name: Verify Pinned & Hashed Dependencies (Supply-Chain Zero-Trust)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `.github/workflows/defense_ci.yml:55` | `quantum-safe` | `git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `.github/workflows/defense_ci.yml:87` | `sovereign` | `- name: Verify Sovereign Command Center CLI Entry Points` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `.github/workflows/defense_ci.yml:89` | `destroyer` | `python destroyer.py --help` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `.github/workflows/defense_ci.yml:123` | `destroyer` | `- name: Verify Production Destroyer Core Extension` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `.github/workflows/defense_ci.yml:319` | `destroyer` | `--certificate-identity-regexp 'https://github\.com/Destroyer-official/Destroyer-ST2027/\.github/workflows/defense_ci\...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `.github/workflows/oqs-rebuild.yml:59` | `quantum-safe` | `https://github.com/open-quantum-safe/liboqs.git "$RUNNER_TEMP/liboqs"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `.gitignore:1` | `military-grade` | `# Secure P2P Military-Grade Communication System` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `LICENSE:3` | `destroyer` | `Copyright (c) 2026 Destroyer-official` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:1` | `sovereign` | `# Sovereign Post-Quantum Communications Architecture (ST2027)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:2` | `zero-trust` | `## High-Assurance Zero-Trust Transport Protocol for National Security Systems over Untrusted Networks` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:14` | `sovereign` | `- **Technical Nomenclature:** Sovereign Transmit 2027 (`Destroyer-ST2027`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:14` | `destroyer` | `- **Technical Nomenclature:** Sovereign Transmit 2027 (`Destroyer-ST2027`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:25` | `sovereign` | `This repository presents the reference implementation, defense specifications, symbolic-model analyses, and operation...` | (b) Standard Identifier | KEEP |
| `README.md:25` | `zero-trust` | `This repository presents the reference implementation, defense specifications, symbolic-model analyses, and operation...` | (b) Standard Identifier | KEEP |
| `README.md:44` | `tactical` | `- **Tactical Military / Radio / Cross-Domain Transit:** Operates over **UDP IPv6** with 1232-byte fixed-rate cell qua...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:47` | `tactical` | `All cryptographic keys, identities, certificates, and tactical directives (MIL-STD-6090 Cursor-on-Target, Two-Person ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:54` | `sovereign` | `## 1. System Architectures: Sovereign Pipeline vs. Quarantined Research Prototype` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:62` | `sovereign` | `\| [A] THE 2027 SOVEREIGN DEFENSE PIPELINE (ST2027 - ACTIVE PRODUCTION TARGET)                             \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:89` | `NC3` | `**Messenger-path honesty (production entry point):** the only supported production network path is `secure_p2p.py nod...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:91` | `nuclear` | `No software-only system can guarantee "nuclear-code" security. This code has **not** undergone FIPS 140-3 CMVP valida...` | (b) Standard Identifier | KEEP |
| `README.md:91` | `TEMPEST shielding` | `No software-only system can guarantee "nuclear-code" security. This code has **not** undergone FIPS 140-3 CMVP valida...` | (b) Standard Identifier | KEEP |
| `README.md:104` | `NC3` | `\| Simulated NC3/EAM/PTT surfaces \| Disabled in production \| command refused \| `--lab` only \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:110` | `top secret` | `\| DPO for TOP SECRET \| Always required \| `AuthorizationError` otherwise \| none \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:179` | `top secret` | `\|                                2027 TOP SECRET COMMUNICATIONS STACK                                     \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:189` | `sovereign` | `\|   ├── Mandatory Overlay (Tor v3 SOCKS5 with remote DNS resolution or Interface-Pinned Sovereign APN)    \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:214` | `SCIF` | `\|   ├── TEMPEST/SCIF host-state probe ONLY (checks facility records/host posture — NOT RF-emanation        \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:226` | `SCIF` | `- **TEMPEST & SCIF Facility Registry (host-state probe ONLY):** Checks host facility records against NATO SDIP-27/28/...` | (b) Standard Identifier | KEEP |
| `README.md:346` | `NC3` | `Architecture & Strategy       Formal Verification & PQC     Doctrine, NC3 & CONOPS         Security Policies & CC` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:367` | `destroyer` | `- incident_response.md                                     - Node Orchestration & Policies (destroyer, policy, ...)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:380` | `tactical` | `1. **[`docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md`](docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:383` | `sovereign` | `4. **[`docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md`](docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md):** Master...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:388` | `sovereign` | `9. **[`docs/OPEN_INTERNET_HARDENING_PLAN.md`](docs/OPEN_INTERNET_HARDENING_PLAN.md):** Strategic blueprint for direct...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:399` | `NC3` | `### 6.3 Research Track 3: High-Consequence Military Operations, Doctrine & NC3 Protocols` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:400` | `nuclear command` | `1. **[`docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md`](docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md):** Nuclear Command (NC3) / DoD ...` | (b) Standard Identifier | KEEP |
| `README.md:400` | `nuclear` | `1. **[`docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md`](docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md):** Nuclear Command (NC3) / DoD ...` | (b) Standard Identifier | KEEP |
| `README.md:400` | `NC3` | `1. **[`docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md`](docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md):** Nuclear Command (NC3) / DoD ...` | (b) Standard Identifier | KEEP |
| `README.md:401` | `tactical` | `2. **[`docs/CONOPS_TACTICAL_DEPLOYMENT.md`](docs/CONOPS_TACTICAL_DEPLOYMENT.md):** Concept of Operations for forward ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:438` | `sovereign` | `12. **[`docs/modules/ca_services.md`](docs/modules/ca_services.md):** Certificate Authority Services — Sovereign PKI ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:446` | `tactical` | `20. **[`docs/modules/destroyer_node.md`](docs/modules/destroyer_node.md):** Tactical Node Orchestrator — Tactical ope...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:453` | `zero-trust` | `27. **[`docs/modules/trust_policy.md`](docs/modules/trust_policy.md):** Zero-Trust Policy Engine — Real-time dynamic ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:459` | `tactical` | `4. **[`docs/README.md`](docs/README.md):** Tactical documentation charter, standards cross-reference guide, and modul...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:494` | `NC3` | `* **Trajectory Charlie: High-Consequence NC3 & Dual-Custody Doctrine:**` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:496` | `tactical` | `* **Trajectory Delta: Systems Engineering & Forward Tactical Deployment:**` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:514` | `zero-trust` | `- **Subcommands:** `auth-keygen`, `auth-sign`, `auth-verify`, `keygen`, `send`, `recv`, `send-file`, `recv-file`, `ch...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:514` | `tactical` | `- **Subcommands:** `auth-keygen`, `auth-sign`, `auth-verify`, `keygen`, `send`, `recv`, `send-file`, `recv-file`, `ch...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:515` | `tactical` | `- **Tactical Military Operations:** Emits ML-DSA-87 signed NATO MIL-STD-6090 Cursor-on-Target beacons (`cot-beacon`),...` | (b) Standard Identifier | KEEP |
| `README.md:525` | `tactical` | `### 4. Tactical C4ISR Operations Console ([`tactical_operator_console.py`](tactical_operator_console.py))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:526` | `tactical` | `A turnkey command-and-control operations terminal designed for tactical field workstations and Joint All-Domain Comma...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:527` | `tactical` | `- **Interactive Operator Terminal:** Command interface for situational awareness, Cursor-on-Target beacon dispatch, a...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:528` | `tactical` | `- **ATAK / WinTAK Multicast Bridge:** Broadcasts standard MIL-STD-6090 CoT XML datagrams over UDP multicast (`239.2.3...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:529` | `tactical` | `- **Voice-Burst Push-to-Talk (PTT):** Simulates tactical radio voice packet bursts encapsulated with monotonic sequen...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:531` | `tactical` | `- **Automated Battle-Readiness Drill:** Invoked via `--drill` to execute end-to-end loopback verification of CoT disp...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:567` | `zero-trust` | `\|   ├── Unit Tests (88 passed)           (Noise-XXhfs, 3-of-5 PKI, SPQR ratchet, ML-DSA/ML-KEM, AEAD vectors, chunki...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:585` | `SCIF` | `\| **NATO SDIP-27/28/29** \| TEMPEST Equipment, SCIF Zoning, Spacing \| [`ts_hw_layer.py:TEMPESTRegistry`](ts_hw_laye...` | (b) Standard Identifier | KEEP |
| `README.md:597` | `sovereign` | `# Clone the sovereign repository` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:598` | `destroyer` | `git clone https://github.com/Destroyer-official/Destroyer-ST2027.git` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:599` | `destroyer` | `cd Destroyer-ST2027` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:699` | `sovereign` | `### 10.9 Unified Sovereign Military Tactical P2P Node (`destroyer_tactical_p2p.py`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:699` | `tactical` | `### 10.9 Unified Sovereign Military Tactical P2P Node (`destroyer_tactical_p2p.py`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:701` | `sovereign` | `The unified sovereign node orchestrates the full post-quantum lifecycle, full-duplex hardware pacing, in-band encrypt...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:725` | `tactical` | `- `/cot <lat> <lon> <call>`: Emits an ML-DSA-87 signed NATO MIL-STD-6090 Cursor-on-Target tactical beacon.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:730` | `tactical` | `### 10.10 DEFCON-1 Tactical Web Command Center (`tactical_web_console.py`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:746` | `classified` | `- **In-Band Classified Messaging**: Encrypted bidirectional transmission with audio/visual alerts.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:754` | `top secret` | `ST2027 provides 5 independent, fail-closed transport channels engineered for classified information up to TOP SECRET ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:754` | `classified` | `ST2027 provides 5 independent, fail-closed transport channels engineered for classified information up to TOP SECRET ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:756` | `tactical` | `1. **Wire-Camouflaged Tactical Comms Channel**:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:766` | `tactical` | `- Real-time tactical tracks signed with FIPS 204 ML-DSA-87 with fail-closed tamper detection.` | (b) Standard Identifier | KEEP |
| `README.md:775` | `tactical` | `# 2. Master Tactical Battle-Readiness Drill (100% In-Band Directives & Purge):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:778` | `battle readiness` | `# 3. Comprehensive Multi-Trial Battle Readiness Suite (12/12 Trials Passed):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:781` | `sovereign` | `# 4. 50X Sovereign Defense Superiority Benchmark (5/5 Vectors Verified):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:793` | `tactical` | `# 8. Tactical Operations Integration Suite (6/6 Passed):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:802` | `tactical` | `The native Rust binary supports zero-Python tactical command execution:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:812` | `tactical` | `# 2. Transmit MIL-STD-6040 tactical message with NSA RTB dirty-word filter:` | (b) Standard Identifier | KEEP |
| `README.md:813` | `tactical` | `./rust_data_plane/target/release/secure-transmit tactical-msg \` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:827` | `tactical` | `### 10.13 Tactical C4ISR Field Console & ATAK/WinTAK Gateway (`tactical_operator_console.py`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:829` | `tactical` | `A unified field operator terminal connecting tactical users to ATAK/WinTAK and defense radio nets:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:840` | `tactical` | `- **MIL-STD-6040 Message Engine:** Routes precedence-tagged tactical orders (`FLASH_OVERRIDE`, `FLASH`, `IMMEDIATE`, ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:845` | `sovereign` | `## 11. Competitor Architectural Analysis & Sovereign Superiority` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `README.md:856` | `SCIF` | `1. **Physical Hardware Independence:** The software platform cannot certify physical tamper-resistance or RF attenuat...` | (b) Standard Identifier | KEEP |
| `README.md:875` | `nuclear` | `- *DoD Directive S-5210.41M: Nuclear Weapon Security Manual: The Two-Person Rule*, Dec 2020.` | (b) Standard Identifier | KEEP |
| `README.md:875` | `weapon` | `- *DoD Directive S-5210.41M: Nuclear Weapon Security Manual: The Two-Person Rule*, Dec 2020.` | (b) Standard Identifier | KEEP |
| `README.md:890` | `sovereign` | `- **Attribution:** Developed for high-assurance communications under the Sovereign Transmit 2027 research program.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `REVIEW_REPORT.md:7` | `destroyer` | `**Repository:** `https://github.com/Destroyer-official/Destroyer-ST2027`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `SECURITY.md:5` | `sovereign` | `**Sovereign Transmit 2027 (ST2027)** is an open reference implementation, mathematical specification, and automated v...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `SECURITY.md:29` | `destroyer` | `2. **Submit Details via GitHub Security Advisories:** Use the [GitHub Security Advisory Reporting Tool](https://githu...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `air_gapped_operation.py:7` | `SCIF` | `Where Used: Isolated command enclaves, SCIF workstations, field stations without` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `air_gapped_operation.py:350` | `zero-trust` | `"Predictable username/hostname fallbacks are prohibited under NIST Level 5+ / zero-trust policy."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `audit_logging_system.py:144` | `zero-trust` | `"Predictable username/hostname fallbacks are prohibited under NIST Level 5+ / zero-trust policy."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `audit_logging_system.py:469` | `state-of-the-art` | `"""State-of-the-art audit logger with database persistence and real-time monitoring."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `balanced_logging.py:19` | `maximum security` | `"THREAT DETECTED", "SECURITY BREACH", "MAXIMUM SECURITY ACHIEVED",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `byzantine_mesh_consensus.py:5` | `tactical` | `Multi-Node Byzantine Fault Tolerant (BFT) Quorum Consensus for Critical Tactical Commands.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `byzantine_mesh_consensus.py:114` | `tactical` | `"""Register an authorized tactical command node and its ML-DSA-87 public key.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `byzantine_mesh_consensus.py:324` | `tactical` | `Supports message-omission tolerant voting in tactical ad-hoc mesh` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `byzantine_mesh_consensus.py:660` | `tactical` | `Autonomously actuate strategic tactical command upon verified M-of-N Byzantine Quorum approval:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `byzantine_mesh_consensus.py:664` | `tactical` | `4. EMERGENCY_SILENCE: Activates tactical cloaking and Poisson background chaff fail-closed.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `byzantine_mesh_consensus.py:775` | `tactical` | `logger.info("[BYZANTINE ACTUATOR] Enforced EMERGENCY_SILENCE (tactical cloaking activated)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ca_services.py:500` | `zero-trust` | `# Zero-trust military authorized peers whitelist` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ca_services.py:583` | `zero-trust` | `"""Add an authorized peer SHA3-512 fingerprint to the zero-trust whitelist."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ca_services.py:1449` | `zero-trust` | `# Zero-Trust Whitelist & Cryptographic TOFU Verification (Finding 1.1)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ca_services.py:1637` | `maximum security` | `ca_logger.info("Creating SSLContext for server with maximum security settings.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ca_services.py:1709` | `maximum security` | `ca_logger.info("SSLContext for server configured with maximum security settings.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ca_services.py:1758` | `maximum security` | `ca_logger.info("Creating SSLContext for client with maximum security settings.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ca_services.py:1828` | `maximum security` | `ca_logger.info("SSLContext for client configured with maximum security settings.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ca_services.py:2047` | `maximum security` | `ca_logger.info("Server socket wrapped with maximum security TLS context")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ca_services.py:2071` | `maximum security` | `ca_logger.info("Client socket wrapped with maximum security TLS context")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cato_continuous_monitoring_engine.py:4` | `sovereign` | `Continuous Authority to Operate (cATO) Runtime Engine for the Sovereign Military Platform.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cato_continuous_monitoring_engine.py:8` | `tactical` | `2. Capability 2: Active Cyber Defense (ACD) automated response & tactical cloaking` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cato_continuous_monitoring_engine.py:13` | `classified` | `and fail-closed authorization gating for classified message transfer.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cato_continuous_monitoring_engine.py:181` | `tactical` | `logger.error(f"Failed to engage tactical cloak playbook: {ex}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/crl.json:4` | `sovereign` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/crl.json:4` | `tactical` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/key_ceremony_affidavit.json:5` | `sovereign` | `"ceremony_id": "CEREMONY-CNSA2-SOVEREIGN-ROOT-2027",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/key_ceremony_affidavit.json:33` | `tactical` | `"name": "Tactical Operations Gamma",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/key_ceremony_affidavit.json:44` | `sovereign` | `"subject": "CN=Sovereign-Defense-Root-CA",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/key_ceremony_affidavit.json:50` | `sovereign` | `"subject": "CN=Sovereign-Tactical-Sub-CA-01",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/key_ceremony_affidavit.json:50` | `tactical` | `"subject": "CN=Sovereign-Tactical-Sub-CA-01",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/key_ceremony_affidavit.json:56` | `sovereign` | `"issuer": "CN=Sovereign-Defense-Root-CA",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/node_alpha.json:5` | `tactical` | `"subject": "CN=tactical-node-alpha.mil,OU=Forward Base Alpha,O=Tactical P2P,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/node_alpha.json:6` | `sovereign` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/node_alpha.json:6` | `tactical` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/node_alpha.json:11` | `tactical` | `"DNS:tactical-node-alpha.mil",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/node_bravo.json:5` | `tactical` | `"subject": "CN=tactical-node-bravo.mil,OU=Forward Base Bravo,O=Tactical P2P,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/node_bravo.json:6` | `sovereign` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/node_bravo.json:6` | `tactical` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/node_bravo.json:11` | `tactical` | `"DNS:tactical-node-bravo.mil",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/pki_manifest.json:10` | `sovereign` | `"root_authority": "CN=Sovereign-Defense-Root-CA",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/sovereign_root_ca.json:3` | `sovereign` | `"subject": "Sovereign-Defense-Root-CA",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `certs/sovereign_root_ca.json:4` | `sovereign` | `"issuer": "Sovereign-Defense-Root-CA",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `certs/sovereign_sub_ca.json:3` | `sovereign` | `"subject": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `certs/sovereign_sub_ca.json:3` | `tactical` | `"subject": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `certs/sovereign_sub_ca.json:4` | `sovereign` | `"issuer": "Sovereign-Defense-Root-CA",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `cjadc2_allied_gateway.py:5` | `tactical` | `DoD CJADC2 Allied & Coalition Cross-Domain Tactical Gateway.` | (b) Standard Identifier | KEEP |
| `cjadc2_allied_gateway.py:20` | `tactical` | `- Packages sanitized tactical data with ML-DSA-87 (FIPS 204) coalition release receipts.` | (b) Standard Identifier | KEEP |
| `cjadc2_allied_gateway.py:334` | `tactical` | `Sanitize, redact, and package tactical data for coalition egress:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cjadc2_cross_domain_guard.py:199` | `classified` | `2. Deep packet content inspection must verify zero classified spillage in egress payload.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cjadc2_cross_domain_guard.py:219` | `classified` | `reason = f"NSA RTB CONTENT INSPECTION FAILURE: Classified indicator or dirty-word detected matching {pat.pattern}"` | (b) Standard Identifier | KEEP |
| `cjadc2_cross_domain_guard.py:436` | `top secret` | `spill_payload = b"CRITICAL TARGET INTEL // TOP SECRET // DO NOT FORWARD"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cjadc2_cross_domain_guard.py:441` | `top secret` | `assert ok is False, "Spillage filter failed to catch TOP SECRET dirty word!"  # nosec: B101` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cjadc2_tactical_cot.py:4` | `tactical` | `MIL-STD-6090 (Active Jan 31, 2025) Cursor-on-Target (CoT) Tactical Situational Awareness` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `cjadc2_tactical_cot.py:12` | `tactical` | `5. Integration into DDIL Tactical Mesh store-and-forward bundles (RFC 9171 / RFC 9172)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `cjadc2_tactical_cot.py:180` | `tactical` | `"""Serializes to bandwidth-efficient JSON for tactical radio links."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `cjadc2_tactical_cot.py:281` | `tactical` | `parser = argparse.ArgumentParser(description="MIL-STD-6090 Cursor-on-Target PQC Tactical Engine")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `cjadc2_tactical_cot.py:293` | `tactical` | `# 1. Create tactical track` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `cjadc2_tactical_cot.py:324` | `tactical` | `print("[PASS] Test 3: Compact tactical JSON roundtrip & signature preserved.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `cjadc2_tactical_cot.py:343` | `tactical` | `print("[PASS] Test 5: DDIL Tactical Mesh store-and-forward bundle packaging verified.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `cjadc2_tactical_cot.py:345` | `tactical` | `print("[ALL 5/5 MIL-STD-6090 TACTICAL CoT TESTS PASSED SUCCESSFULLY]")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `cnsa2_policy_engine.py:547` | `tactical` | `- 'private_apn' (Cellular 5G Core Network Slicing / Tactical APN)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cnsa2_policy_engine.py:549` | `tactical` | `- 'air_gapped' / 'wireguard' (Tactical P2P overlay)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cnsa2_policy_engine.py:583` | `tactical` | `f"without Private APN, Tor onion routing, or tactical overlay is prohibited in "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `cnsa_purity.py:3` | `top secret` | `cnsa_purity.py — CNSA 2.0 strictness enforcement for the TOP SECRET path.` | (b) Standard Identifier | KEEP |
| `compliance_reports/ato_authorization_decision.json:6` | `sovereign` | `"system_name": "Sovereign Military P2P Tactical Mesh (Destroyer-P2P)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/ato_authorization_decision.json:6` | `destroyer` | `"system_name": "Sovereign Military P2P Tactical Mesh (Destroyer-P2P)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/ato_authorization_decision.json:6` | `tactical` | `"system_name": "Sovereign Military P2P Tactical Mesh (Destroyer-P2P)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/canary_pilot_telemetry.json:22` | `tactical` | `"title": "Tactical Cloaking & Zero Public Socket Egress",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/canary_pilot_telemetry.json:24` | `tactical` | `"details": "Direct public IP blocked; tactical overlay subnet (10.99.0.0/16) permitted"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cavp_validation_report.json:3` | `sovereign` | `"module_name": "SecureP2P Sovereign Cryptographic Module",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cjadc2_cross_domain_audit.json:31` | `classified` | `"details": "NSA RTB CONTENT INSPECTION FAILURE: Classified indicator or dirty-word detected matching \\bTOP\\s+SECRET...` | (b) Standard Identifier | KEEP |
| `compliance_reports/cjadc2_data_fabric_drill_report.json:5` | `tactical` | `"lifecycle_phase": "Phase 6: Tactical Data Fabric, Cross-Domain MLS & Dynamic PQC Crypto-Agility",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cmvp_fips140_3_submittal.json:5` | `sovereign` | `"module_name": "Secure P2P Sovereign Cryptographic Module",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cmvp_fips140_3_submittal.json:11` | `sovereign` | `"vendor_name": "Sovereign Defense Communications Consortium (draft author)"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cmvp_fips140_3_submittal.json:35` | `tactical` | `{"role": "Tactical User", "type": "Mutual ML-DSA-87 Certificate Authenticated", "services": ["Double Ratchet Session"...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cmvp_fips140_3_submittal.json:38` | `tactical` | `{"service": "FIPS 203 ML-KEM-1024 Key Agreement", "approved": true, "roles": ["Tactical User"]},` | (b) Standard Identifier | KEEP |
| `compliance_reports/cmvp_fips140_3_submittal.json:39` | `tactical` | `{"service": "FIPS 204 ML-DSA-87 Digital Signature", "approved": true, "roles": ["Cryptographic Officer", "Tactical Us...` | (b) Standard Identifier | KEEP |
| `compliance_reports/cmvp_fips140_3_submittal.json:41` | `tactical` | `{"service": "FIPS 197 AES-256-GCM AEAD Encryption", "approved": true, "roles": ["Tactical User"]},` | (b) Standard Identifier | KEEP |
| `compliance_reports/cmvp_fips140_3_submittal.json:42` | `tactical` | `{"service": "FIPS 202 SHA3-512 & SHAKE-256 Digest", "approved": true, "roles": ["Tactical User", "Cryptographic Offic...` | (b) Standard Identifier | KEEP |
| `compliance_reports/cmvp_fips140_3_submittal.json:43` | `tactical` | `{"service": "Cryptographic Zeroization (sodium_memzero)", "approved": true, "roles": ["Cryptographic Officer", "Tacti...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/conops_operational_profile.json:4` | `tactical` | `"document_id": "CONOPS-TACTICAL-P2P-2028-V1",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/conops_operational_profile.json:5` | `sovereign` | `"title": "Concept of Operations (CONOPS): Sovereign Military Tactical P2P Communications Mesh",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/conops_operational_profile.json:5` | `tactical` | `"title": "Concept of Operations (CONOPS): Sovereign Military Tactical P2P Communications Mesh",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/conops_operational_profile.json:22` | `tactical` | `"name": "Tactical Edge Mobile Relay (Forward Operating Base)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/conops_operational_profile.json:23` | `tactical` | `"network_type": "Private Tactical Cellular / Mesh Radio (MIL-STD)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/conops_operational_profile.json:58` | `tactical` | `"title": "Tactical Node Operator (TNO)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/conops_operational_profile.json:62` | `tactical` | `"Initiate emergency tactical zeroization upon physical overrun threat"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/csrmc_phase5_drill_report.json:5` | `tactical` | `"lifecycle_phase": "Phase 5: Operations Phase & Tactical Resilience",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/csrmc_phase5_drill_report.json:37` | `tactical` | `"standard": "RFC 9172 BPsec / Tactical Edge Triad Architecture (TETA)",` | (b) Standard Identifier | KEEP |
| `compliance_reports/cyclonedx_cbom.json:13` | `sovereign` | `"name": "Sovereign Military Defense P2P Platform",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:15` | `sovereign` | `"description": "NSA CNSA 2.0 & FIPS 140-3 Sovereign Tactical Communications Asset"` | (b) Standard Identifier | KEEP |
| `compliance_reports/cyclonedx_cbom.json:15` | `tactical` | `"description": "NSA CNSA 2.0 & FIPS 140-3 Sovereign Tactical Communications Asset"` | (b) Standard Identifier | KEEP |
| `compliance_reports/cyclonedx_cbom.json:21` | `sovereign` | `"name": "Sovereign Defense Architecture Directorate",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:53` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:79` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:104` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:128` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:152` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:217` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:236` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:258` | `quantum-safe` | `"quantumSecurity": "quantum-safe"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:264` | `sovereign` | `"name": "Mutual TLS 1.3 with Sovereign ML-DSA-87 Certificates",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:265` | `sovereign` | `"version": "RFC 8446 Strict Sovereign Profile",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/cyclonedx_cbom.json:274` | `quantum-safe` | `"quantumSecurity": "quantum-safe"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/defense_master_audit_receipt.json:13` | `zero-trust` | `"details": "186 tests passed (148 lib incl. TPM 2.0 NV rollback guard, S-01/S-02 replay protection, Noise-XXhfs, 3-of...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/dod_zero_trust_assessment.json:224` | `tactical` | `"name": "Tactical Network Cloaking"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/independent_redteam_assessment.json:2` | `classified` | `"assessment_kind": "SELF-ASSESSMENT (internal adversarial drill). NOT independent, NOT classified, NOT authoritative....` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/independent_redteam_assessment.json:13` | `sovereign` | `"MITRE ATT&CK for Enterprise & Sovereign P2P Protocols"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/independent_redteam_assessment.json:79` | `sovereign` | `"implementation": "Mutual Sovereign Post-Quantum ML-DSA-87 PKI authentication; CAC/PIV smart card integration; zero a...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/independent_redteam_assessment.json:107` | `tactical` | `"initial_access_cost": "EXTREMELY_HIGH (Requires physical compromise of tamper-responding Level 4 HSM or private tact...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/independent_redteam_assessment.json:118` | `tactical` | `"Route all strategic node traffic through Private Tactical APN or Tor v3 onion overlay.",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/independent_redteam_assessment.json:119` | `classified` | `"Engage an independent assessor and, for classified use, the NIAP/CMVP/CSfC pipeline before any authorization request."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/niap_common_criteria_matrix.json:48` | `sovereign` | `"name": "X.509 Certificate Validation (Sovereign PQ PKI)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/niap_common_criteria_matrix.json:97` | `tactical` | `"standard": "DoD Network Concealment / Tor SOCKS5 & Private Tactical APN",` | (b) Standard Identifier | KEEP |
| `compliance_reports/oscal_sar_cato.json:31` | `sovereign` | `"title": "Sovereign Military Defense Platform - Continuous Security Assessment Results (SAR) & POA&M",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/oscal_sar_cato.json:52` | `tactical` | `"title": "Tactical Hardware HSM Micro-Firmware Upgrades"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/oscal_ssp_cnsa2.json:5` | `sovereign` | `"title": "Sovereign Military P2P Communications Platform - System Security Plan (SSP)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/oscal_ssp_cnsa2.json:30` | `sovereign` | `"id": "sovereign-defense-hq",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/oscal_ssp_cnsa2.json:32` | `sovereign` | `"name": "Sovereign Defense Communications Command",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/oscal_ssp_cnsa2.json:44` | `sovereign` | `"system-name": "Sovereign Military P2P Tactical Mesh",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/oscal_ssp_cnsa2.json:44` | `tactical` | `"system-name": "Sovereign Military P2P Tactical Mesh",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/oscal_ssp_cnsa2.json:45` | `destroyer` | `"system-name-short": "Destroyer-P2P",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/oscal_ssp_cnsa2.json:46` | `zero-trust` | `"description": "Quantum-resistant, zero-trust, peer-to-peer tactical communications platform utilizing native FIPS 20...` | (b) Standard Identifier | KEEP |
| `compliance_reports/oscal_ssp_cnsa2.json:46` | `tactical` | `"description": "Quantum-resistant, zero-trust, peer-to-peer tactical communications platform utilizing native FIPS 20...` | (b) Standard Identifier | KEEP |
| `compliance_reports/oscal_ssp_cnsa2.json:52` | `NC3` | `"title": "National Security Communications (NC3 & Defense Mesh)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/oscal_ssp_cnsa2.json:53` | `tactical` | `"description": "Tactical voice, text, telemetry, and critical command authentication data.",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/oscal_ssp_cnsa2.json:123` | `zero-trust` | `"description": "Access Enforcement: Strict Zero-Trust RBAC engine enforces least privilege and default-deny.",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `compliance_reports/ssdf_self_attestation.json:163` | `sovereign` | `"product": "Secure P2P Sovereign Communications Engine v2.0.0-CNSA2-2027",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `core/orchestrator.py:960` | `maximum security` | `"""Enforce maximum security - delegates to security module."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `critical_release.py:2` | `nuclear` | `"""Two-person critical-release authority (nuclear-release discipline).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `crypto_selftest.py:4` | `top secret` | `tests + entropy-source policy for the TOP SECRET session path.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `decentralized_architecture.py:7` | `tactical` | `Where Used: Serverless ad-hoc tactical networking, peer discovery without central rendezvous,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `decentralized_architecture.py:2937` | `tactical` | `# IP-tactical-only: Direct IP peer addresses; MITM scope neutralized by CERT_REQUIRED + pinned CA anchor.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `dep_impl.py:366` | `maximum security` | `- For maximum security, allocate sensitive data using SecureMemory allocator` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `dep_impl.py:739` | `maximum security` | `and software approaches for maximum security.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `dep_impl.py:974` | `maximum security` | `# If all protections are active, we're at maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `deploy/openssl_cnsa.cnf:2` | `destroyer` | `# Destroyer-ST2027 - OpenSSL CNSA 2.0 TLS posture overlay (P1, 2026-10-16)` | (b) Standard Identifier | KEEP |
| `destroyer.py:3` | `sovereign` | `DESTROYER ST2027 — SOVEREIGN DEFENSE COMMAND CENTER` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:3` | `destroyer` | `DESTROYER ST2027 — SOVEREIGN DEFENSE COMMAND CENTER` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `destroyer.py:6` | `NC3` | `NSA CNSA Suite 2.0 // FIPS 203 / 204 / 205 // DoD S-5210.41M NC3` | (b) Standard Identifier | KEEP |
| `destroyer.py:9` | `tactical` | `1. Tactical Web Console (DEFCON-1 Mission Control GUI)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:10` | `sovereign` | `2. Sovereign Tactical P2P Node (Hardware-Paced Wire Camouflage)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:10` | `tactical` | `2. Sovereign Tactical P2P Node (Hardware-Paced Wire Camouflage)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:14` | `sovereign` | `6. 50X Sovereign Defense Superiority Benchmark Drill` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:44` | `sovereign` | `"""Print the sovereign DEFCON-1 tactical banner."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:44` | `tactical` | `"""Print the sovereign DEFCON-1 tactical banner."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:47` | `sovereign` | `║              DESTROYER ST2027 // SOVEREIGN MILITARY COMMAND CENTER                   ║` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:47` | `destroyer` | `║              DESTROYER ST2027 // SOVEREIGN MILITARY COMMAND CENTER                   ║` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `destroyer.py:48` | `top secret` | `║         [TOP SECRET // NSA CNSA SUITE 2.0 // NOFORN // ZERO SINGLE-POINT-TRUST]       ║` | (b) Standard Identifier | KEEP |
| `destroyer.py:54` | `nuclear command` | `• Nuclear Command NC3  : Two-Person Rule Universal EAM (120-Second Temporal Lifetime)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:54` | `nuclear` | `• Nuclear Command NC3  : Two-Person Rule Universal EAM (120-Second Temporal Lifetime)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:54` | `NC3` | `• Nuclear Command NC3  : Two-Person Rule Universal EAM (120-Second Temporal Lifetime)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:112` | `tactical` | `"""Launch the Tactical Web Console (DEFCON-1 GUI)."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:113` | `tactical` | `print(f"\n{BOLD}{CYAN}[COMMAND] Launching Tactical Web Console on http://localhost:8080...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:119` | `sovereign` | `"""Launch the Sovereign Tactical P2P Node."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:119` | `tactical` | `"""Launch the Sovereign Tactical P2P Node."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:120` | `sovereign` | `print(f"\n{BOLD}{CYAN}[COMMAND] Launching Sovereign Tactical P2P Node ({role})...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:120` | `tactical` | `print(f"\n{BOLD}{CYAN}[COMMAND] Launching Sovereign Tactical P2P Node ({role})...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:133` | `tactical` | `cmd = [sys.executable, str(target), "chat", "--data-plane", "rust", "--tactical-cloak"]` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `destroyer.py:270` | `sovereign` | `"""Run the 50X Sovereign Defense Superiority empirical benchmark."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:271` | `sovereign` | `print(f"\n{BOLD}{CYAN}[COMMAND] Running 50X Sovereign Superiority Empirical Benchmark...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:277` | `tactical` | `"""Run the two-terminal automated tactical drill (NORAD vs Pentagon)."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:278` | `tactical` | `print(f"\n{BOLD}{CYAN}[COMMAND] Running Automated Tactical P2P Drill (NORAD vs Pentagon)...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:284` | `tactical` | `"""Run DoD CJADC2 Phase 6 Tactical Data Fabric & MLS Cross-Domain Guard Drill."""` | (b) Standard Identifier | KEEP |
| `destroyer.py:285` | `tactical` | `print(f"\n{BOLD}{CYAN}[COMMAND] Running DoD CJADC2 Phase 6 Tactical Data Fabric Mission Drill...{RESET}")` | (b) Standard Identifier | KEEP |
| `destroyer.py:291` | `sovereign` | `"""Execute live simulation drill of the seL4 Sovereign Appliance MILS Architecture."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:293` | `sovereign` | `print(f"{BOLD}{CYAN}  DESTROYER ST2027 // EAL6+ seL4 SOVEREIGN HARDWARE APPLIANCE DRILL             {RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:293` | `destroyer` | `print(f"{BOLD}{CYAN}  DESTROYER ST2027 // EAL6+ seL4 SOVEREIGN HARDWARE APPLIANCE DRILL             {RESET}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `destroyer.py:305` | `sovereign` | `print(f"\n{GREEN}[STAGE 2] Instantiating Dual Sovereign Nodes (NORAD_ALPHA & PENTAGON_BRAVO)...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:314` | `sovereign` | `print(f"{CYAN}          - Sovereign: 256-bit CSfC Pre-Shared Key (RFC 8784 Anti-Quantum PSK){RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:320` | `top secret` | `order = b"FLASH TOP SECRET // EYES ONLY // DEFCON-1 AUTHORIZATION GRANTED"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:339` | `sovereign` | `print(f"  [DRILL SUCCESSFUL] EAL6+ seL4 SOVEREIGN APPLIANCE 100% OPERATIONAL")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:344` | `tactical` | `"""Spawn dual tactical military terminals in separate console windows."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:345` | `tactical` | `print(f"\n{BOLD}{CYAN}[COMMAND] Spawning Dual Military Tactical P2P Terminals (NORAD Alpha & Pentagon Bravo)...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:415` | `sovereign` | `print(f"\n{BOLD}{CYAN}SOVEREIGN COMMAND CENTER — SELECT MISSION MODULE:{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:416` | `tactical` | `print(f"  {GREEN}[1] Tactical Web Console (DEFCON-1 Mission Control GUI on localhost:8080){RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:417` | `sovereign` | `print(f"  {GREEN}[2] Sovereign Tactical P2P Node (Hardware-Paced Military Enclave){RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:417` | `tactical` | `print(f"  {GREEN}[2] Sovereign Tactical P2P Node (Hardware-Paced Military Enclave){RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:420` | `tactical` | `print(f"  {GREEN}[5] Spawn Dual Tactical Military Terminals Side-by-Side (NORAD vs Pentagon){RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:421` | `tactical` | `print(f"  {CYAN}[6] Execute DoD CJADC2 Phase 6 Tactical Data Fabric & MLS Cross-Domain Drill{RESET}")` | (b) Standard Identifier | KEEP |
| `destroyer.py:423` | `sovereign` | `print(f"  {CYAN}[8] Run 50X Sovereign Defense Superiority Empirical Benchmark{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:424` | `tactical` | `print(f"  {CYAN}[9] Run Two-Terminal Automated Tactical Drill (In-Process Demo){RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:426` | `sovereign` | `print(f"  {MAGENTA}[11] Run Sovereign seL4 Hardware Appliance MILS Drill (RED/CRYPTO/BLACK){RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:469` | `sovereign` | `parser = argparse.ArgumentParser(description="Destroyer ST2027 Sovereign Military Command Center")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:469` | `destroyer` | `parser = argparse.ArgumentParser(description="Destroyer ST2027 Sovereign Military Command Center")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `destroyer.py:471` | `tactical` | `choices=["interactive", "web", "tactical", "alpha", "bravo", "chat",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:480` | `tactical` | `elif args.mode in ("tactical", "alpha", "bravo"):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer.py:481` | `tactical` | `launch_tactical_node("interactive" if args.mode == "tactical" else args.mode)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer_tactical_p2p.py:3` | `sovereign` | `DESTROYER STRATEGIC P2P: SOVEREIGN TOP SECRET COMMUNICATIONS NODE` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer_tactical_p2p.py:3` | `top secret` | `DESTROYER STRATEGIC P2P: SOVEREIGN TOP SECRET COMMUNICATIONS NODE` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer_tactical_p2p.py:3` | `destroyer` | `DESTROYER STRATEGIC P2P: SOVEREIGN TOP SECRET COMMUNICATIONS NODE` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `destroyer_tactical_p2p.py:6` | `zero-trust` | `Zero-Trust: Zero Central Servers, Zero Cloud Relays, Zero Metadata Leaks` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer_tactical_p2p.py:9` | `sovereign` | `This module re-exports the sovereign tactical node components from secure_p2p.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `destroyer_tactical_p2p.py:9` | `tactical` | `This module re-exports the sovereign tactical node components from secure_p2p.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/ARCHITECTURE.md:1` | `sovereign` | `# System Architecture — Sovereign Post-Quantum Direct P2P Messaging` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ARCHITECTURE.md:31` | `sovereign` | `### A. 2027 Sovereign Top-Secret Pipeline (`secure_transmit_2027.py`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ARCHITECTURE.md:35` | `sovereign` | `[0] Anonymity Overlay (Tor v3 SOCKS5 / Sovereign APN / WireGuard) ... transport_anonymity.py` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ARCHITECTURE.md:71` | `sovereign` | `→ Constant-Rate Scheduler (50ms / 20 cells/sec) → SOCKS5 Tor / Sovereign Tunnel` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ARCHITECTURE.md:91` | `sovereign` | `\| **Anonymity Overlay** \| Tor v3 SOCKS5 / Sovereign APN \| RFC 1928, Loopix / Sphinx Packet Design \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ARCHITECTURE.md:98` | `tactical` | `- **Continuous Epoch Ratchet (CER) with hybrid ML-KEM-1024 / P-384 interleaving:** the primary tactical channel (`sec...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md:1` | `sovereign` | `# ST2027: Architectural Comparison & Sovereign Enclave Analysis` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md:13` | `sovereign` | `However, high-consequence sovereign military command-and-control (C2), tactical enclaves, and Top Secret cross-domain...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md:13` | `top secret` | `However, high-consequence sovereign military command-and-control (C2), tactical enclaves, and Top Secret cross-domain...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md:13` | `tactical` | `However, high-consequence sovereign military command-and-control (C2), tactical enclaves, and Top Secret cross-domain...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md:24` | `sovereign` | `\| Security Dimension \| Signal (Open Whisper Systems) \| WhatsApp (Meta) \| Telegram \| Commercial CDS Diodes (Owl, ...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md:41` | `sovereign` | `## 3. Deep Architectural Breakdown of the 7 Sovereign Pillars` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md:65` | `tactical` | `- **Out-of-Band SAS Verification:** Derives a 16-character Short Authentication String (SAS, e.g. `9F2A-4B81-C03D-7E1...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md:66` | `quantum-safe` | `- **Quantum-Safe PSK Option:** Supports pre-shared keys via `--psk-file` conforming to RFC 8773 (argv secrets strictl...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md:87` | `sovereign` | `* **The Operational Requirement:** Tactical and sovereign communications must function during WAN disruption, without...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/COMPETITOR_ANALYSIS_AND_SOVEREIGN_SUPERIORITY.md:87` | `tactical` | `* **The Operational Requirement:** Tactical and sovereign communications must function during WAN disruption, without...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:1` | `sovereign` | `# Concept of Operations (CONOPS): Sovereign Military Tactical P2P Communications Mesh` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:1` | `tactical` | `# Concept of Operations (CONOPS): Sovereign Military Tactical P2P Communications Mesh` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:4` | `tactical` | `- **Document ID:** `CONOPS-TACTICAL-P2P-2028-V1`` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:5` | `sovereign` | `- **Classification:** UNCLASSIFIED // TECHNICAL CONOPS FOR SOVEREIGN DEFENSE SYSTEMS` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:8` | `zero-trust` | `- **Operational Target:** Post-Quantum Zero-Trust Data Plane & Simplex Optical Cross-Domain Transit` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:13` | `sovereign` | `The Sovereign Military Tactical P2P Communications Mesh (`Destroyer-P2P` / `Destroyer-ST2027`) provides quantum-secur...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:13` | `destroyer` | `The Sovereign Military Tactical P2P Communications Mesh (`Destroyer-P2P` / `Destroyer-ST2027`) provides quantum-secur...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:13` | `tactical` | `The Sovereign Military Tactical P2P Communications Mesh (`Destroyer-P2P` / `Destroyer-ST2027`) provides quantum-secur...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:24` | `tactical` | `\| **ENV-EDGE** \| Tactical Edge Mobile Relay \| Private Cellular APN / UHF Mesh \| Tier-5 (EW / SIGINT Intercept) \|...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:26` | `classified` | `\| **ENV-CROSS-DOMAIN** \| Classified Enclave Transfer \| Simplex Single-Strand Optical Diode \| Tier-6 (Multi-Enclav...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:42` | `tactical` | `3. **Tactical Node Operator (TNO)**:` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:45` | `tactical` | `- Enforces `--tactical-cloak` and executes emergency sanitization commands upon breach warning.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:56` | `tactical` | `### 5.1 Normal Tactical Mode` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:62` | `tactical` | `### 5.2 Tactical Cloaked Mode (`P2P_TACTICAL_CLOAK=1`)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:64` | `tactical` | `- **Permitted Paths**: Loopback, RFC 1918 private subnets, and tactical overlay tunnels (`10.99.0.0/16`).` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:71` | `classified` | `- **Anti-Penetration Assurance**: Compromise of the receiving station cannot physically pivot across the optical diod...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:98` | `tactical` | `## 6. Tactical Deployment Topologies & Workflows` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:103` | `classified` | `\| Classified Enclave (RED)  \|                      \| Deployed Receiver (BLACK) \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:105` | `tactical` | `\| [Tactical Workstation]    \|                      \| [Station Terminal]        \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:135` | `tactical` | `│    [Tactical Burst Message Injected Into Stream]    │` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:141` | `tactical` | `- Both units run `stream-chaff` continuously over ad-hoc tactical radios.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:154` | `tactical` | `│ [Tactical Command Message Embedded In 1232B Cell]  │` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:157` | `tactical` | `│ [Tactical Response Message Embedded In 1232B Cell] │` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:190` | `classified` | `# On the Transmitting Station (Classified Enclave):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:231` | `tactical` | `### SOP-5: Deploying Full-Duplex Paced Tactical Enclave Channel` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:265` | `sovereign` | `### SOP-7: Deploying Unified Sovereign Command Center & Field Terminals` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:288` | `tactical` | `- `/cot <lat> <lon> <call>`: Emits signed Cursor-on-Target tactical military beacon` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:293` | `tactical` | `### SOP-8: Launching DEFCON-1 Tactical Web Operations Console` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:305` | `classified` | `- In-Band Classified Tactical Comms & MIL-STD-6090 Cursor-on-Target dispatcher` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:305` | `tactical` | `- In-Band Classified Tactical Comms & MIL-STD-6090 Cursor-on-Target dispatcher` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:308` | `sovereign` | `- 50X Sovereign Defense Superiority matrix comparison table` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:311` | `tactical` | `### SOP-9: Tactical C4ISR Operator Console & ATAK/WinTAK Multicast Gateway` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:313` | `tactical` | `# Launch interactive Tactical C4ISR Operator Console:` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:325` | `tactical` | `# 2. Transmit MIL-STD-6040 tactical message with RTB dirty-word filter:` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:326` | `tactical` | `./rust_data_plane/target/release/secure-transmit tactical-msg \` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:338` | `tactical` | `- Push-to-Talk (PTT) tactical voice burst simulator with cryptographic integrity headers.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:351` | `classified` | `- RED interfaces (plaintext classified) and BLACK interfaces (encrypted ciphertext) MUST remain bound to physically d...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:364` | `sovereign` | `## 9. 50X Sovereign Defense Superiority & Assurance Metrics` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:366` | `sovereign` | `The ST2027 sovereign military baseline is empirically benchmarked against consumer messaging standards (Signal, Whats...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/CONOPS_TACTICAL_DEPLOYMENT.md:368` | `sovereign` | `\| Defense Vector \| Consumer Messaging Standard \| ST2027 Sovereign Baseline \| Advantage Factor \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/DEFENSE_HARDENING_MASTER_PLAN.md:1` | `sovereign` | `# Sovereign Transmit 2027 (ST2027) — Defense Hardening Master Plan` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/DEFENSE_HARDENING_MASTER_PLAN.md:240` | `tactical` | `1. **Primary Tactical Channel:** Operates an epoch-based KEM ratchet (continuous hybrid ratcheting where every $N$ me...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/DEFENSE_HARDENING_MASTER_PLAN.md:640` | `sovereign` | `## Phase 6: Sovereign 50X Defense Hardening & Standalone Native Data Plane Expansion` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/DEFENSE_HARDENING_MASTER_PLAN.md:677` | `sovereign` | `### [x] Task 6.6: Automated 50X Sovereign Defense Superiority Benchmark (COMPLETED & VERIFIED)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/DEFENSE_HARDENING_MASTER_PLAN.md:680` | `sovereign` | `- **Verification Gate:** Automated execution returns `[VERDICT] 50X SOVEREIGN DEFENSE SUPERIORITY MATHEMATICALLY & EM...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/EVALUATION_DOSSIER.md:1` | `sovereign` | `# Sovereign Transmit 2027 (ST2027) — Technical Evaluation Dossier` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/EVALUATION_DOSSIER.md:5` | `tactical` | `**Assurance Level:** Formal Symbolic & Bounded Model Checked Tactical Transport Baseline` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/EVALUATION_DOSSIER.md:14` | `sovereign` | `This document provides formal cryptographic, architectural, and empirical proof resolving 100% of findings raised in ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/EVALUATION_DOSSIER.md:16` | `sovereign` | `ST2027 is engineered as an air-gap-capable, sovereign, tactical cryptographic transport. It enforces:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/EVALUATION_DOSSIER.md:16` | `tactical` | `ST2027 is engineered as an air-gap-capable, sovereign, tactical cryptographic transport. It enforces:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/EVALUATION_DOSSIER.md:37` | `mission-critical` | `- **Memory Hygiene Boundary:** Python immutable `bytes` objects cannot be deterministically zeroized by user code due...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/EVALUATION_DOSSIER.md:124` | `sovereign` | `Every architectural and implementation flaw identified in earlier reviews has been addressed with mathematically soun...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/EVALUATION_DOSSIER.md:124` | `tactical` | `Every architectural and implementation flaw identified in earlier reviews has been addressed with mathematically soun...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FIPS_140_3_SECURITY_POLICY.md:2` | `sovereign` | `## Secure P2P Sovereign Cryptographic Module v2.0.0-CNSA2-2027` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FIPS_140_3_SECURITY_POLICY.md:8` | `sovereign` | `- **Module Name:** Secure P2P Sovereign Cryptographic Module` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FIPS_140_3_SECURITY_POLICY.md:63` | `tactical` | `2. **Tactical User**:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FIPS_140_3_SECURITY_POLICY.md:72` | `top secret` | `Synchronous power-up Known Answer Tests (KATs) run automatically prior to cryptographic initialization in the 2027 To...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FIPS_140_3_SECURITY_POLICY.md:96` | `top secret` | `- Static AST inspection via `crypto_selftest.check_no_weak_rng()` strictly forbidding import or use of Python's pseud...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md:17` | `military-grade` | `Those corrections improve the implementation. They do **not** establish military-grade security, formal verification,...` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md:17` | `classified` | `Those corrections improve the implementation. They do **not** establish military-grade security, formal verification,...` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md:26` | `classified` | `\| Controlled external security evaluation \| **CONDITIONAL GO, tightly scoped** \| Authorized test environment, synt...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md:28` | `classified` | `\| Military, classified, strategic-command, or safety-critical operational use \| **NO-GO** \| The present evidence c...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md:44` | `destroyer` | `- Final Git HEAD: `db73f07e3b6e1d9a866e7c5f6e33545c3d77e94c` (`Merge pull request #1 from Destroyer-official/audit/de...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md:89` | `tactical` | `- **Application/orchestration plane:** a large Python codebase handles identity, peer orchestration, policy, hardware...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md:90` | `tactical` | `- **Native data plane:** Rust modules implement framing, AEAD, replay handling, padding/chaff, handshake/ratchet comp...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md:92` | `tactical` | `- **Network boundary:** peers, relays, DHT/TLS/UDP paths, and tactical inputs are untrusted until authenticated and a...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md:289` | `tactical` | `**Conclusion:** the repository should not advertise “better than Signal,” “PQ3 superiority,” or WhatsApp-equivalent i...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_CURRENT.md:423` | `classified` | `### Military/classified/strategic use — NO-GO` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_REMEDIATION_PLAN.md:1` | `destroyer` | `# Destroyer-ST2027 Security Remediation Plan` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_REMEDIATION_PLAN.md:9` | `classified` | `This plan covers defects confirmed by direct source inspection and executable regressions in the current working tree...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_REMEDIATION_PLAN.md:37` | `classified` | `A green focused suite can support continued development only. It cannot establish resistance to a capable adversary, ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_3_REMEDIATION.md:1` | `destroyer` | `# Destroyer-ST2027: Third Independent Forensic Security Audit Remediation` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_3_REMEDIATION.md:3` | `destroyer` | `**Target Baseline:** `Destroyer-ST2027` (Commit `face4f9` to `a341c34`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_3_REMEDIATION.md:5` | `top secret` | `**Classification Posture:** TOP SECRET // SCI // NOFORN // CNSA 2.0 Pure` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_3_REMEDIATION.md:13` | `destroyer` | `This document details the engineering and cryptographic remediation of all findings (S-01 through S-09) from the thir...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_3_REMEDIATION.md:28` | `destroyer` | `\| **S-08** \| Low \| `aead.rs`, `pacing.rs`, `main.rs` \| Key reuse across primitives (same 32B key for AES-GCM and ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_4_REMEDIATION.md:1` | `destroyer` | `# Destroyer-ST2027: Fourth Forensic Security Audit Remediation` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_4_REMEDIATION.md:3` | `destroyer` | `**Target Baseline:** `Destroyer-ST2027` (audit cycle 2026-10-17), repository root `D:\code\Main_projects\p2p\p2p_6_1-26`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_4_REMEDIATION.md:4` | `tactical` | `**Audit Scope:** Fourth independent forensic review of the Python control plane and tactical modules: signature verif...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_4_REMEDIATION.md:44` | `destroyer` | `\| **A4-10** \| Medium \| `destroyer.py` (diode PSK) \| Hardcoded, world-known PSK written to a shared temp path for ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_4_REMEDIATION.md:127` | `destroyer` | `Core modules: `hybrid_kex.py`, `secure_key_manager.py`, `remote_siem_forwarder.py`, `tactical_operator_console.py`, `...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:3` | `sovereign` | `**Target:** `Destroyer-ST2027` sovereign tactical P2P mesh` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:3` | `destroyer` | `**Target:** `Destroyer-ST2027` sovereign tactical P2P mesh` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:3` | `tactical` | `**Target:** `Destroyer-ST2027` sovereign tactical P2P mesh` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:14` | `tactical` | `security-critical tactical modules. It records the defects confirmed in this` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:23` | `NC3` | `- NC3 command paths, EAM custody, CJADC2 cross-domain gateway.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:50` | `NC3` | `report trust anchors, NC3 identity provisioning, WORM chains, DDIL` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:107` | `NC3` | `7. **Tactical operation** — DDIL bundles, CJADC2 cross-domain guard, NC3` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:107` | `tactical` | `7. **Tactical operation** — DDIL bundles, CJADC2 cross-domain guard, NC3` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:121` | `NC3` | `threshold downgrade, predictable onion keys, NC3 fallback keys, and` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:131` | `NC3` | `\| E-04 \| HIGH \| NC3 identity provisioning \| In-process code could mint tactical officer identities in production ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:131` | `tactical` | `\| E-04 \| HIGH \| NC3 identity provisioning \| In-process code could mint tactical officer identities in production ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:141` | `tactical` | `\| E-14 \| HIGH \| Tactical replay \| Inbound tactical datagrams lacked replay deduplication across console restarts ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:158` | `tactical` | `3. **Tactical Replay Defense (`tactical_operator_console.py`):**` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:159` | `tactical` | `- Enforced deduplication window across all tactical message types (`COT_EVENT`, `TACTICAL_MSG`, `PTT_VOICE`).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:214` | `destroyer` | `\| Dimension \| Destroyer-ST2027 \| Signal \| WhatsApp \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:218` | `tactical` | `\| Metadata protection \| Tactical anonymity features, but no sealed-sender equivalent found \| Strong metadata minim...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:222` | `NC3` | `\| Tactical/offline \| DDIL, air-gap, diode, CJADC2, NC3 \| Not a tactical/NC3 platform \| Not a tactical/NC3 platfor...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:222` | `tactical` | `\| Tactical/offline \| DDIL, air-gap, diode, CJADC2, NC3 \| Not a tactical/NC3 platform \| Not a tactical/NC3 platfor...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:226` | `destroyer` | `Destroyer-ST2027 is stronger than consumer messengers for post-quantum` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:227` | `NC3` | `migration, tactical disruption tolerance, NC3 controls, and signed audit` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:227` | `tactical` | `migration, tactical disruption tolerance, NC3 controls, and signed audit` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:243` | `NC3` | `\| NC3 and CJADC2 \| B+ \| Custody, replay, and trust-anchor issues fixed; no external command-system accreditation \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:244` | `tactical` | `\| DDIL and tactical data \| A- \| Per-bundle HKDF, epoch rotation, binding, and zeroization added; automated key dis...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_21.md:293` | `NC3` | `- Provision NC3 officer credentials out of band; confirm no in-process minting.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:2` | `destroyer` | `## DESTROYER-ST2027 TACTICAL DEFENSE & POST-QUANTUM MESSAGING ENCLAVE` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:2` | `tactical` | `## DESTROYER-ST2027 TACTICAL DEFENSE & POST-QUANTUM MESSAGING ENCLAVE` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:3` | `destroyer` | `**Evaluation Target:** `Destroyer-ST2027` (Baseline 2026-10-24)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:4` | `sovereign` | `**Classification Intent:** Sovereign Defense / Tactical DDIL / CJADC2 Tactical Operations` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:4` | `tactical` | `**Classification Intent:** Sovereign Defense / Tactical DDIL / CJADC2 Tactical Operations` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:13` | `NC3` | `**CONDITIONALLY SUITABLE FOR CONTROLLED AIR-GAPPED EVALUATION & FIELD PILOTS; STRICTLY NOT AUTHORIZED FOR LIVE STRATE...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:25` | `sovereign` | `- **F-07 (MEDIUM):** Sovereign Group Ratchet epoch synchronization gap resolved via automatic roster-wide key re-deri...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:33` | `tactical` | `The audit inspected the complete repository across 356 files spanning Python tactical runtimes, Rust deterministic mi...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:37` | `destroyer` | `\| **Tactical Runtime Core** \| [destroyer.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/destroyer.py), [secure_tr...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:37` | `tactical` | `\| **Tactical Runtime Core** \| [destroyer.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/destroyer.py), [secure_tr...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:42` | `tactical` | `\| **Cross-Domain & Tactical Diode** \| [cjadc2_cross_domain_guard.py](file:///d:/code/Main_projects/p2p/p2p_6_1-26/c...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:50` | `tactical` | `- **Pytest Master Suite:** 1,500+ tests verified across cryptographic KATs, exploit regressions, tactical diode simul...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:58` | `sovereign` | `The Destroyer-ST2027 platform operates as a multi-tier sovereign defense communications enclave designed for conteste...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:58` | `destroyer` | `The Destroyer-ST2027 platform operates as a multi-tier sovereign defense communications enclave designed for conteste...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:58` | `tactical` | `The Destroyer-ST2027 platform operates as a multi-tier sovereign defense communications enclave designed for conteste...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:63` | `destroyer` | `\|   CLI (destroyer.py)  \|  Tactical Web Console  \|  CJADC2 CoT Tactical Mesh    \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:63` | `tactical` | `\|   CLI (destroyer.py)  \|  Tactical Web Console  \|  CJADC2 CoT Tactical Mesh    \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:68` | `tactical` | `\|                      TACTICAL ENCRYPTION & RATCHET LAYER                      \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:69` | `sovereign` | `\|   Double Ratchet (PQ-v2) \| Sovereign Group Ratchet \| CNSA 2.0 Post-Quantum     \|` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:83` | `sovereign` | `\|                      SOVEREIGN HARDWARE ATTESTATION                           \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:89` | `tactical` | `1. **Red/Black Domain Separation:** Red domain contains plaintext tactical orders and decrypted C2 commands; Black do...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:100` | `tactical` | `- **Exploitation Impact:** CI/CD and deployment gating failed closed with "DEFENSE DEFICIENCY DETECTED", preventing a...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:118` | `classified` | `- **Exploitation Impact:** Rejection during FIPS 140-3 and NSA accreditation submittal; algorithm non-compliance in c...` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:119` | `sovereign` | `- **Remediation:** Standardized sovereign and high-assurance modes strictly on `AES-256-GCM` with 96-bit nonces, veri...` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:133` | `sovereign` | `### F-07: Sovereign Group Ratchet Multi-Party Synchronization Gap (MEDIUM)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:151` | `sovereign` | `\| **F-07** \| Sovereign Group Ratchet Multi-Party Sync Gap \| **MEDIUM** \| Certain \| [sovereign_group_ratchet.py](...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:154` | `tactical` | `\| **F-10** \| Tactical Web Console Session Lifetime in Memory \| **LOW** \| High \| [tactical_web_console.py](file:/...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:167` | `sovereign` | `- **Sovereign Group Ratchet (MLS Aligned):** Implements epoch-based sender key ratchets with Two-Person Integrity (TP...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:175` | `destroyer` | `## G. Comparative Assessment: Destroyer-ST2027 vs Signal vs WhatsApp` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:177` | `destroyer` | `\| Security Dimension \| Destroyer-ST2027 \| Signal Protocol \| WhatsApp \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:183` | `sovereign` | `\| **Group Messaging Architecture** \| Sovereign MLS-Aligned Ratchet with TPI \| Sender Keys via pairwise channels \|...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:184` | `NC3` | `\| **Two-Person Integrity (NC3/C2)** \| **Enforced (Dual ML-DSA-87 Co-signing)** \| None (Single user control) \| Non...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:185` | `tactical` | `\| **Network Infrastructure** \| **Pure P2P / DDIL Tactical Radio Diode** \| Centralized Signal servers \| Centralize...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:218` | `zero-trust` | `\| **Identity & Access Control** \| **93 / 100** \| High Assurance \| 3-of-5 PKI multi-sig, ML-DSA-87 device certific...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:219` | `tactical` | `\| **Data & Metadata Protection** \| **88 / 100** \| Strong \| Tactical diode unicast, cover traffic, VirtualLock mem...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:223` | `tactical` | `\| **OVERALL SECURITY ASSURANCE** \| **91 / 100** \| **HIGH ASSURANCE** \| **Suitable for tactical field pilot and co...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:241` | `tactical` | `\| PHASE 2: TACTICAL FIELD PILOT READINESS (NEXT 30-60 DAYS)                     \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:243` | `tactical` | `\| - Validate DDIL tactical mesh performance across real HF/UHF radio modems     \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:266` | `sovereign` | `\| **Classified Strategic NC3 / SAP Handover** \| **FULL GO (FOR ACCREDITATION HANDOVER)** \| Genuine Ed25519 custodi...` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:266` | `classified` | `\| **Classified Strategic NC3 / SAP Handover** \| **FULL GO (FOR ACCREDITATION HANDOVER)** \| Genuine Ed25519 custodi...` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_FINAL_2026_10_24.md:266` | `NC3` | `\| **Classified Strategic NC3 / SAP Handover** \| **FULL GO (FOR ACCREDITATION HANDOVER)** \| Genuine Ed25519 custodi...` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:2` | `sovereign` | `## Destroyer-ST2027: Sovereign Strategic Top Secret Defense Communications` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:2` | `top secret` | `## Destroyer-ST2027: Sovereign Strategic Top Secret Defense Communications` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:2` | `destroyer` | `## Destroyer-ST2027: Sovereign Strategic Top Secret Defense Communications` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:16` | `sovereign` | `\| **F-05** \| **High** \| Python runtime memory zeroization unreliable \| CPython immutable `bytes` copies cannot be...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:20` | `sovereign` | `\| **F-09** \| **Medium** \| Tor TCP-only; UDP path lacks anonymity \| Tor v3 carries TCP only; tactical UDP is direc...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:20` | `tactical` | `\| **F-09** \| **Medium** \| Tor TCP-only; UDP path lacks anonymity \| Tor v3 carries TCP only; tactical UDP is direc...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:23` | `sovereign` | `\| **F-12** \| **Info** \| No sovereign group messaging protocol \| System lacked group ratchet. Implement **CNSA Sui...` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:43` | `sovereign` | `5. **Phase 5: Sovereign Group Protocol (F-12) & Architecture Documentation (F-08, F-09)**` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:49` | `tactical` | `7. **Phase 7: Deep Forensic Static Audit Remediation & Tactical Core Hardening**` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:50` | `NC3` | `- **TACT-01 (NC3 Two-Person Rule EAM)**: Enforced dual distinct officer ML-DSA-87 signatures over canonical EAM envel...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_PLAN.md:56` | `destroyer` | `- **Finding 04 (Rust State Rollback & Nonce Reuse)**: Upgraded state file layout to 80-byte authenticated structure (...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_REPORT_2026_10_26.md:24` | `classified` | `\| **Classified / Strategic Command (NC3)** \| NO-GO \| **NO-GO** *(Lab Pilot Ready)* \| Requires physical NVLAP labo...` | (b) Standard Identifier | KEEP |
| `docs/FORENSIC_SECURITY_AUDIT_REMEDIATION_REPORT_2026_10_26.md:24` | `NC3` | `\| **Classified / Strategic Command (NC3)** \| NO-GO \| **NO-GO** *(Lab Pilot Ready)* \| Requires physical NVLAP labo...` | (b) Standard Identifier | KEEP |
| `docs/FULL_CODEBASE_SECURITY_REVIEW_2026_10.md:5` | `sovereign` | `Target: `Destroyer-ST2027` sovereign peer-to-peer system (repository root` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FULL_CODEBASE_SECURITY_REVIEW_2026_10.md:5` | `destroyer` | `Target: `Destroyer-ST2027` sovereign peer-to-peer system (repository root` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FULL_CODEBASE_SECURITY_REVIEW_2026_10.md:16` | `NC3` | `- Command-and-control (NC3 EAM, CJADC2 gateway, critical release, group` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FULL_CODEBASE_SECURITY_REVIEW_2026_10.md:51` | `NC3` | `\| C5 \| NC3 war key \| Deterministic public-constant fallback for the war key \| Missing or invalid key material rai...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FULL_CODEBASE_SECURITY_REVIEW_2026_10.md:57` | `sovereign` | `\| C11 \| Sovereign group ratchet \| TPI rekey advanced epochs without officer signatures \| Exactly two enrolled off...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FULL_CODEBASE_SECURITY_REVIEW_2026_10.md:79` | `NC3` | `remediation pass covering audit logging, monitoring, NC3 consoles, CJADC2,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/FULL_CODEBASE_SECURITY_REVIEW_2026_10.md:80` | `destroyer` | `decentralized DHT/relay, destroyer modules, hardware/TEE, PKI identity,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/KEY_CEREMONY.md:1` | `top secret` | `# Offline 3-of-5 Threshold CA Key Ceremony (TOP SECRET)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/KEY_CEREMONY.md:22` | `top secret` | `- TOP SECRET root and identity certificates: **3-of-5**` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/KEY_CEREMONY.md:25` | `top secret` | `sub-CA and test roots only, never for the TOP SECRET root.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:1` | `military-grade` | `# Sovereign Military-Grade NC3 Deployment & Operations Manual` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:1` | `sovereign` | `# Sovereign Military-Grade NC3 Deployment & Operations Manual` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:1` | `NC3` | `# Sovereign Military-Grade NC3 Deployment & Operations Manual` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:10` | `mission-critical` | `This manual establishes the mandatory operational protocols, cryptographic controls, physical hardware baselines, and...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:10` | `sovereign` | `This manual establishes the mandatory operational protocols, cryptographic controls, physical hardware baselines, and...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:10` | `nuclear command` | `This manual establishes the mandatory operational protocols, cryptographic controls, physical hardware baselines, and...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:10` | `nuclear` | `This manual establishes the mandatory operational protocols, cryptographic controls, physical hardware baselines, and...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:10` | `NC3` | `This manual establishes the mandatory operational protocols, cryptographic controls, physical hardware baselines, and...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:10` | `destroyer` | `This manual establishes the mandatory operational protocols, cryptographic controls, physical hardware baselines, and...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:40` | `NC3` | `### 3.2. Phase 2: NC3 / PAL Two-Person Integrity (TPI) Dual-Custody Protocol` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:42` | `nuclear` | `- **Doctrinal Alignment**: DoD Directive S-5210.41M (*Nuclear Weapon Personnel Reliability and Two-Person Rule*) & CJ...` | (b) Standard Identifier | KEEP |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:42` | `weapon` | `- **Doctrinal Alignment**: DoD Directive S-5210.41M (*Nuclear Weapon Personnel Reliability and Two-Person Rule*) & CJ...` | (b) Standard Identifier | KEEP |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:73` | `tactical` | `### 3.5. Phase 5: Air-Gapped Simplex Tactical Data Diode` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:81` | `tactical` | `- **Tactical Format**: Native Cursor-on-Target (CoT) XML event encoding for blue-force situational awareness, target ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:96` | `NC3` | `### SOP-02: Transmitting an Emergency Action Message (/nc3-send)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:100` | `NC3` | `/nc3-send FLASH-DEFCON1-STRIKE-PLAN TARGET-VECTOR-OMNI <CLASSIFIED_PAL_CODE>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:107` | `NC3` | `### SOP-03: Authenticating and Unsealing an EAM (/nc3-verify)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:112` | `NC3` | `/nc3-verify <OFFICER_1_ID> <OFFICER_2_ID>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:157` | `sovereign` | `# 4. Sovereign NC3 & TPI Verification Suites` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md:157` | `NC3` | `# 4. Sovereign NC3 & TPI Verification Suites` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md:1` | `sovereign` | `# Sovereign Transmit 2027 (ST2027) — High-Assurance Transport Architecture Specification for National Security Systems` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md:15` | `sovereign` | `**Sovereign Transmit 2027 (ST2027)** is an advanced, post-quantum secure communications architecture engineered for N...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md:15` | `tactical` | `**Sovereign Transmit 2027 (ST2027)** is an advanced, post-quantum secure communications architecture engineered for N...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md:46` | `tactical` | `\|   ├── Simplex Optical Tactical Data Diode FEC (`tactical_data_diode.py`)                           \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md:185` | `top secret` | `Keys for `TOP SECRET // SCI // NOFORN` cannot be computed from or downgraded to `SECRET // REL TO USA, FVEY` keys.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md:187` | `tactical` | `### 5.2 Simplex Optical Tactical Data Diode` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md:189` | `classified` | `For cross-domain boundary transit between RED (classified) and BLACK (unclassified) enclaves, ST2027 provides a **Sim...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md:195` | `sovereign` | `## 6. Sovereign Ephemeral Ratchet & Two-Person Integrity (TPI)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md:197` | `sovereign` | `Multi-party tactical groups communicate via the **Sovereign Group Ratchet** (`sovereign_group_ratchet.py` and `rust_d...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/NSS_HIGH_ASSURANCE_ARCHITECTURE_ST2027.md:197` | `tactical` | `Multi-party tactical groups communicate via the **Sovereign Group Ratchet** (`sovereign_group_ratchet.py` and `rust_d...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/OPEN_INTERNET_HARDENING_PLAN.md:5` | `sovereign` | `Goal: sovereign military messaging over the public internet — government/` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/OPEN_INTERNET_HARDENING_PLAN.md:137` | `nuclear` | `tracks, required before any TS/nuclear use): HSM attestation, WORM/SIEM audit,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/OPEN_INTERNET_HARDENING_PLAN.md:219` | `sovereign` | `## PART J — 2027 Sovereign Top-Secret Pipeline Integration (The 5 Strategic Pillars)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/OPEN_INTERNET_HARDENING_PLAN.md:221` | `sovereign` | `Following the open-internet hardening phases above, the system was formalized into the **2027 Sovereign Top-Secret Co...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/OPEN_INTERNET_HARDENING_PLAN.md:226` | `sovereign` | `4. **Pillar 4 (Transport Anonymity & Cell Shaping):** `transport_anonymity.py`, `spo_dpo.py` — Tor v3 SOCKS5 (RFC 192...` | (b) Standard Identifier | KEEP |
| `docs/OPEN_INTERNET_HARDENING_PLAN.md:229` | `NC3` | `**Verification Status:** Validated by 120 Python tests + 64 Rust data plane tests (184 total tests green) with machin...` | (b) Standard Identifier | KEEP |
| `docs/README.md:1` | `sovereign` | `# Sovereign Secure Communications Architecture — Documentation Index` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/README.md:3` | `sovereign` | `This directory contains the engineering specifications, operational doctrine, compliance targets, and formal verifica...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/README.md:13` | `tactical` | `├── TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md # Tactical Communications Technical Manual (TM-ST2027-2027.1)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/README.md:23` | `sovereign` | `├── ST2027_SPEC.md                           # Top-Secret sovereign transport specification & wire formats` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/README.md:26` | `sovereign` | `├── OPEN_INTERNET_HARDENING_PLAN.md          # Sovereign Direct IPv6 P2P Transport & Hardening Blueprint` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/README.md:30` | `tactical` | `├── CONOPS_TACTICAL_DEPLOYMENT.md            # Tactical concept of operations in DDIL environments` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/README.md:35` | `nuclear command` | `├── MILITARY_NC3_DEPLOYMENT_GUIDE.md         # Nuclear command & dual-custody (DoD S-5210.41M) manual` | (b) Standard Identifier | KEEP |
| `docs/README.md:35` | `nuclear` | `├── MILITARY_NC3_DEPLOYMENT_GUIDE.md         # Nuclear command & dual-custody (DoD S-5210.41M) manual` | (b) Standard Identifier | KEEP |
| `docs/README.md:75` | `zero-trust` | `└── trust_policy.md                      # Zero-trust policy evaluation and attestation claims` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/README.md:120` | `military-grade` | `1. **No Marketing Buzzwords:** Terms such as "military-grade" or "quantum-proof" must be accompanied by exact cryptog...` | (b) Standard Identifier | KEEP |
| `docs/README.md:120` | `quantum-proof` | `1. **No Marketing Buzzwords:** Terms such as "military-grade" or "quantum-proof" must be accompanied by exact cryptog...` | (b) Standard Identifier | KEEP |
| `docs/RESTRUCTURE_PLAN.md:1` | `military-grade` | `# RESTRUCTURE PLAN — Professional Military-Grade Project Layout` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RESTRUCTURE_PLAN.md:85` | `NC3` | `│       │   ├── officers.py         # sealed officer credentials (was nc3 get_or_create part)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RESTRUCTURE_PLAN.md:90` | `nuclear` | `│       ├── nc3/                    # nuclear-release domain (isolated, audited separately)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RESTRUCTURE_PLAN.md:90` | `NC3` | `│       ├── nc3/                    # nuclear-release domain (isolated, audited separately)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RESTRUCTURE_PLAN.md:94` | `NC3` | `│       │   └── cli.py              # /nc3-send /nc3-verify /zeroize handlers (was inline in app.py)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RESTRUCTURE_PLAN.md:189` | `NC3` | `NC3: `nc3_nuclear_command.py`→`nc3/{eam,pal}.py` (+officers→`identity/officers.py`);` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RESTRUCTURE_PLAN.md:190` | `NC3` | ``critical_release.py`→`nc3/custody.py`; EAM CLI blocks→`nc3/cli.py`.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RUST_CORE.md:32` | `zero-trust` | `\| Zero-Trust verification \| `zero_trust_engine.py` \| `zero_trust.rs` — NIST SP 800-207 continuous per-packet risk ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RUST_CORE.md:135` | `zero-trust` | ``threat-eval`, `zero-trust-eval`, `cot-beacon`, `tactical-msg`, `eam-auth`,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RUST_CORE.md:135` | `tactical` | ``threat-eval`, `zero-trust-eval`, `cot-beacon`, `tactical-msg`, `eam-auth`,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RUST_CORE.md:138` | `zero-trust` | `cookie gate, ACD defense, zero-trust, memory-guard).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/RUST_CORE.md:159` | `destroyer` | `Destroyer-official/Destroyer-ST2027`; prior waves committed).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SEL4_EAL6_PLUS_SOVEREIGN_APPLIANCE_SPEC.md:1` | `sovereign` | `# Sovereign Transmit 2027 (ST2027): EAL6+ seL4 Sovereign Hardware Appliance Specification & Master Implementation Plan` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SEL4_EAL6_PLUS_SOVEREIGN_APPLIANCE_SPEC.md:4` | `top secret` | `**Classification Target:** TOP SECRET / SCI / NC3 Strategic Communications` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SEL4_EAL6_PLUS_SOVEREIGN_APPLIANCE_SPEC.md:4` | `NC3` | `**Classification Target:** TOP SECRET / SCI / NC3 Strategic Communications` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SEL4_EAL6_PLUS_SOVEREIGN_APPLIANCE_SPEC.md:76` | `sovereign` | `\| Attack Vector             \| Traditional EAL6+ Gap                 \| ST2027 Sovereign Countermeasure              \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SEL4_EAL6_PLUS_SOVEREIGN_APPLIANCE_SPEC.md:123` | `sovereign` | `\|   \|                    (The Sovereign Native Core)                     \|                               \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SEL4_EAL6_PLUS_SOVEREIGN_APPLIANCE_SPEC.md:174` | `sovereign` | `<!-- 2. CRYPTO Protection Domain: The Sovereign Cryptographic Engine -->` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOP.md:1` | `sovereign` | `# Program SOP — Sovereign Secure P2P Operations` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SOP.md:49` | `sovereign` | `- Transmitted in constant-rate 50ms ticks using 1232-byte cells with AES-256-CTR whitening over Tor v3 / sovereign AP...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:1` | `sovereign` | `# Sovereign Transmit 2027 (ST2027) — Military High-Assurance Specification & Implementation Plan` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:2` | `sovereign` | `## High-Assurance Sovereign Information Exchange Architecture for Classified & Tactical Operations` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:2` | `classified` | `## High-Assurance Sovereign Information Exchange Architecture for Classified & Tactical Operations` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:2` | `tactical` | `## High-Assurance Sovereign Information Exchange Architecture for Classified & Tactical Operations` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:4` | `sovereign` | `**Author:** Sovereign Defense Communications Group` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:17` | `sovereign` | `\|                       CIVILIAN DESIGN FLAW vs. SOVEREIGN MILITARY DEFENSE                              \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:22` | `sovereign` | `\|    - ST2027 Sovereign: Zero central servers. Pure point-to-point (P2P), tactical radio links, dark     \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:22` | `tactical` | `\|    - ST2027 Sovereign: Zero central servers. Pure point-to-point (P2P), tactical radio links, dark     \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:28` | `sovereign` | `\|    - ST2027 Sovereign: Zero phone numbers, zero user accounts. Identities are non-exportable hardware-  \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:35` | `sovereign` | `\|    - ST2027 Sovereign: Strict 50.0 ms (20 Hz) constant-rate clock emitting uniform 1232-byte cells.    \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:41` | `sovereign` | `\|    - ST2027 Sovereign: OS-level non-pageable memory locking (VirtualLock/mlock), TPM PCR state drift   \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:46` | `sovereign` | `\|    - ST2027 Sovereign: Dual-Person Authorization (DPA / Two-Person Rule) requiring cryptographic      \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:52` | `sovereign` | `\|    - ST2027 Sovereign: Hardware Simplex Optical Data Diode support. Photons physically travel in only  \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:77` | `sovereign` | `\|                             SOVEREIGN TRANSMIT 2027 DEFENSE ARCHITECTURE                               \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:80` | `sovereign` | `\|    - ML-DSA-87 Sovereign Root CA & Offline Key Ceremony (scripts/witnessed_key_ceremony.py)          \|` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:84` | `tactical` | `\|  [PILLAR 4] ZERO-METADATA TRAFFIC INVARIANCE & TACTICAL TRANSPORT                                      \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:89` | `tactical` | `\|    - Dual Transport: Mode A (Direct Tactical UDP/IPv6) \| Mode B (Tor v3 SOCKS5 Onion Routing)          \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:117` | `sovereign` | `To achieve absolute sovereign security and eliminate any possible audit critique, we execute this 5-phase engineering...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:158` | `sovereign` | `- **Task 5.1:** Require high-consequence messages to contain an enveloped DPA manifest co-signed by two distinct ML-D...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:160` | `sovereign` | `- **Task 5.3:** Receiver station verifies both signatures against the sovereign root anchor before releasing payload ...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SOVEREIGN_MILITARY_TRANSIT_SPEC_AND_PLAN.md:179` | `sovereign` | `## 6. Conclusion: From Commercial Chat to Sovereign Defense` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/ST2027_HARDENING_ROADMAP.md:13` | `NC3` | `- Simulated NC3/EAM/PTT commands refused on the production message path.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_IMPLEMENTATION_PLAN.md:7` | `nuclear command` | `the exact same rigor as a nuclear command directive."*` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_IMPLEMENTATION_PLAN.md:7` | `nuclear` | `the exact same rigor as a nuclear command directive."*` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_IMPLEMENTATION_PLAN.md:88` | `SCIF` | `procurement (HSM, SCIF, diode devices, seL4 hardware).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_MUTUAL_AUTH_HARDENING.md:32` | `NC3` | `- simulated `/eam`, `/nc3-verify`, and `/ptt` commands (refused at the` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_MUTUAL_AUTH_HARDENING.md:128` | `NC3` | `and refuses simulated NC3/EAM/PTT commands in production.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_MUTUAL_AUTH_HARDENING.md:160` | `nuclear` | `"nuclear-code" security.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_MUTUAL_AUTH_HARDENING.md:170` | `top secret` | `3. **Hardware custody.** Software key files are not a root of trust. TOP SECRET` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_MUTUAL_AUTH_HARDENING.md:191` | `NC3` | `NC3/EAM/PTT/CoT code still exists for lab exercises and is refused on the` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_RESEARCH_SOURCES_2026-09-30.md:129` | `sovereign` | `- Lesson: sender/receiver anonymity involves mixes, cover traffic, topology, adversary assumptions, and latency trade...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_RESEARCH_SOURCES_2026-09-30.md:173` | `classified` | `- Lesson: validation applies to specific modules and operational environments. The page identifies 21 September 2026 ...` | (b) Standard Identifier | KEEP |
| `docs/ST2027_RESEARCH_SOURCES_2026-09-30.md:197` | `classified` | `- Lesson: OQS explicitly describes research/prototyping limitations and best-effort response. Existing use of liboqs ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_RESEARCH_SOURCES_2026-09-30.md:213` | `classified` | `- **Blocked:** https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity-Resources/ and https://www.nsa.gov/Resour...` | (b) Standard Identifier | KEEP |
| `docs/ST2027_SPEC.md:1` | `sovereign` | `# Sovereign Transmit 2027 (ST2027) — Military High-Assurance Specification & Implementation Plan` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:3` | `sovereign` | `## High-Assurance Sovereign Information Exchange Architecture for Classified & Tactical Operations` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:3` | `classified` | `## High-Assurance Sovereign Information Exchange Architecture for Classified & Tactical Operations` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:3` | `tactical` | `## High-Assurance Sovereign Information Exchange Architecture for Classified & Tactical Operations` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:5` | `sovereign` | `**Author:** Sovereign Defense Communications Group` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:24` | `sovereign` | `\|                       CIVILIAN DESIGN FLAW vs. SOVEREIGN MILITARY DEFENSE                              \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:29` | `sovereign` | `\|    - ST2027 Sovereign: Zero central servers. Pure point-to-point (P2P), tactical radio links, dark     \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:29` | `tactical` | `\|    - ST2027 Sovereign: Zero central servers. Pure point-to-point (P2P), tactical radio links, dark     \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:35` | `sovereign` | `\|    - ST2027 Sovereign: Zero phone numbers, zero user accounts. Identities are non-exportable hardware-  \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:42` | `sovereign` | `\|    - ST2027 Sovereign: Strict 50.0 ms (20 Hz) constant-rate clock emitting uniform 1232-byte cells.    \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:50` | `sovereign` | `\|    - ST2027 Sovereign: OS-level non-pageable memory locking (VirtualLock/mlock in ts_rt; best-effort   \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:56` | `sovereign` | `\|    - ST2027 Sovereign: Dual-Person Authorization (two-person control per DoD surety doctrine, §2.9)     \|` | (b) Standard Identifier | KEEP |
| `docs/ST2027_SPEC.md:62` | `sovereign` | `\|    - ST2027 Sovereign: Optical data-diode simplex path (no ACKs; Reed-Solomon FEC reconstruction)      \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:70` | `NC3` | `WireGuard-precedent band of <4,000). Experimental NC3 prototypes and research spikes stay in `archive/` and` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:113` | `nuclear` | `9. **Two-person control:** DoD nuclear surety doctrine — the two-person rule as "the most important aspect of` | (b) Standard Identifier | KEEP |
| `docs/ST2027_SPEC.md:139` | `tactical` | `## 3. Architecture: Iron Core, Session Layer, and the Three Tactical Modes` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:167` | `tactical` | `### 3.3 The Three Tactical Modes` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:208` | `SCIF` | `Blocked on procurement/process (not code): HSM deployment, SCIF/TEMPEST accreditation, diode devices, seL4` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPEC.md:261` | `sovereign` | `codepoints (0x11EB/0x11EC/0x11ED) installed. (4) "CNSA 2.0 Sovereign Max" branding removed (fabricated tier).` | (b) Standard Identifier | KEEP |
| `docs/ST2027_SPECIFICATION.md:1` | `destroyer` | `# Destroyer-ST2027 Protocol Specification: High-Assurance Post-Quantum Communications Architecture` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPECIFICATION.md:12` | `destroyer` | `Destroyer-ST2027 is a dual-profile, post-quantum communication system engineered for hostile network environments und...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPECIFICATION.md:25` | `tactical` | `## 2. Dual Protocol Profiles: Tactical vs. Deniable` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPECIFICATION.md:31` | `destroyer` | `│      DESTROYER-ST2027         │` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPECIFICATION.md:38` | `tactical` | `│   (Tactical Defense & C2)     │                 │   (Deniable E2EE Messaging)   │` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/ST2027_SPECIFICATION.md:50` | `tactical` | `\| Security Property \| `ST2027-TAC` (Tactical / C2) \| `ST2027-HUMAN` (Deniable Messaging) \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:7` | `classified` | `**Classification:** UNCLASSIFIED — no classified information is contained` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:82` | `tactical` | `execute strategic commands under M-of-N quorum, move tactical data` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:83` | `nuclear` | `across a coalition gateway with quarantine and audit, and run nuclear` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:103` | `tactical` | `\| Tier 1 — Tactical/DDIL \| BPsec bundles, store-and-forward mesh, chaff, caps \| Complete \| `test_production_tier1...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:104` | `classified` | `\| Tier 2 — Classified trade \| CNSA enforcement, 2027 gate, quarantine, TUF/SBOM/CBOM, ceremony, HSM, TLS \| Complet...` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:436` | `nuclear command` | `### 5.4 Nuclear command (dual control)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:436` | `nuclear` | `### 5.4 Nuclear command (dual control)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:515` | `NC3` | `\| 12 \| NC3 single-officer/token-swap/scheme-flip \| always \| Dual-control violations refused \| NC3 suites + live ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:547` | `NC3` | `\| Live NC3 transfer \| `test_nc3_two_terminal_live_transfer.py` \| Two-terminal EAM over PQ link, dual unseal, zeroi...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:554` | `NC3` | `\| Ceremony/NC3 \| quorum, token, KMI, two-person suites \| Dual control end to end \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:588` | `classified` | `status is claimed or implied. Deployment to classified networks` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:1026` | `military-grade` | `Air-Gapped Operation Support for Military-Grade P2P Messaging.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:2545` | `military-grade` | `Anti-Forensics Module - Military-Grade Plausible Deniability` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:4032` | `tactical` | `Multi-Node Byzantine Fault Tolerant (BFT) Quorum Consensus for Critical Tactical Commands.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:4092` | `tactical` | `Register an authorized tactical command node and its ML-DSA-87 public key.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:4129` | `tactical` | `Supports message-omission tolerant voting in tactical ad-hoc mesh` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:4238` | `tactical` | `Autonomously actuate strategic tactical command upon verified M-of-N Byzantine Quorum approval:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:4242` | `tactical` | `4. EMERGENCY_SILENCE: Activates tactical cloaking and Poisson background chaff fail-closed.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:4610` | `zero-trust` | `Add an authorized peer SHA3-512 fingerprint to the zero-trust whitelist.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:4813` | `military-grade` | `Perform quantum-resistant certificate exchange with military-grade security.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:4815` | `military-grade` | `Implements a military-grade multi-layer security protocol:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:4819` | `military-grade` | `4. Military-grade authenticated encryption (XChaCha20-Poly1305)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:4977` | `military-grade` | `Military-grade secure erasure of all cryptographic material from memory following DoD 5220.22-M / NIST SP 800-88.` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:5343` | `tactical` | `DoD CJADC2 Allied & Coalition Cross-Domain Tactical Gateway.` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:5358` | `tactical` | `- Packages sanitized tactical data with ML-DSA-87 (FIPS 204) coalition release receipts.` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:5456` | `tactical` | `Sanitize, redact, and package tactical data for coalition egress:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:5616` | `classified` | `2. Deep packet content inspection must verify zero classified spillage in egress payload.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:5682` | `tactical` | `MIL-STD-6090 (Active Jan 31, 2025) Cursor-on-Target (CoT) Tactical Situational Awareness` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:5690` | `tactical` | `5. Integration into DDIL Tactical Mesh store-and-forward bundles (RFC 9171 / RFC 9172)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:5754` | `tactical` | `Serializes to bandwidth-efficient JSON for tactical radio links.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:5963` | `tactical` | `- 'private_apn' (Cellular 5G Core Network Slicing / Tactical APN)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:5965` | `tactical` | `- 'air_gapped' / 'wireguard' (Tactical P2P overlay)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:6228` | `military-grade` | `This module implements continuous security monitoring for the military-grade` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:6956` | `military-grade` | `Military-grade covert channel resistance for secure P2P messaging.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:7739` | `nuclear` | `Two-person critical-release authority (nuclear-release discipline).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:10200` | `military-grade` | `Production-ready decentralized architecture for military-grade P2P messaging.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:11854` | `maximum security` | `- For maximum security, allocate sensitive data using SecureMemory allocator` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:12007` | `maximum security` | `and software approaches for maximum security.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:12950` | `military-grade` | `Dependency Security Verification System - Military-Grade Implementation` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:12983` | `military-grade` | `Military-grade dependency security verification system.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:13274` | `tactical` | `Orchestrates tactical canary node deployment and collects continuous` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:13311` | `tactical` | `Verify tactical cloaking router prohibits raw public IP egress.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:13744` | `NC3` | `3. Message Origin Authentication & Non-Repudiation: High-assurance per-message post-quantum digital signatures (FALCO...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:14455` | `maximum security` | `- For maximum security, use bytearray for sensitive data storage` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:15522` | `maximum security` | `SecurityError: Always raises this error to maintain maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:15538` | `maximum security` | `This method always returns the MAXIMUM security level settings,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:17674` | `military-grade` | `Security Enhancements - Military-Grade` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:17675` | `military-grade` | `Military-grade security features for the secure P2P system` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:17680` | `military-grade` | `Military security levels military-grade` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:17692` | `military-grade` | `This class implements the military-grade quantum-resistant protections` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:17755` | `military-grade` | `including military-grade microarchitectural attacks.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:17948` | `military-grade` | `Implements military-grade zero-knowledge proofs for military privacy` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:18153` | `military-grade` | `military-grade secure P2P messaging. Provides cryptographically secure random` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:20459` | `sovereign` | `for the Sovereign Military Communications Platform under DoD Continuous ATO (cATO).` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:20496` | `sovereign` | `mapped to NIST SP 800-53 Rev 5 and CNSSI 1253 for the Sovereign Military Defense Platform.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:22731` | `maximum security` | `This function is designed for maximum security with FALCON-1024 signatures` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:22752` | `maximum security` | `No fallbacks or downgrades are permitted for maximum security.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:22775` | `classified` | `remains the accredited path for classified use).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:22928` | `maximum security` | `Hybrid Strategy for Maximum Security:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:23392` | `military-grade` | `MILITARY-GRADE HYBRID KEY ENCAPSULATION MECHANISM` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:23400` | `maximum security` | `This implementation provides maximum security by combining two fundamentally different` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:23507` | `maximum security` | `This implementation provides maximum security and flexibility:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24158` | `tactical` | `sanitization, and real-time live tactical network execution.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24174` | `classified` | `TRIAL 9: Top-Secret Classified File Transfer (128KB SHA3-512 Verified)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24311` | `maximum security` | `Maximum Security Hardening Module` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24329` | `maximum security` | `Exception raised when maximum security requirements cannot be met.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24335` | `maximum security` | `def __init__(self, message: str = "Maximum security requirements failed", details: Optional[Dict[str, Any]] = None)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24362` | `maximum security` | `Maximum Security Hardening implementation with no fallbacks.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24374` | `maximum security` | `Initialize maximum security hardening.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24536` | `maximum security` | `Enforce maximum security requirements with no fallbacks.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24557` | `maximum security` | `Enforce maximum security or fail the application.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24569` | `maximum security` | `Main function for testing maximum security hardening.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24584` | `classified` | `• §4-2: Memory Protection Requirements for Classified Information Systems` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:24669` | `maximum security` | `and memory protection extensions for maximum security isolation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:25381` | `military-grade` | `to ensure perfect military-grade security compliance.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:25408` | `maximum security` | `Enable maximum security hardening.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:25482` | `military-grade` | `Memory Protection Engine - Military-Grade Memory Corruption Defense` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:26104` | `military-grade` | `Production-ready metadata resistance features for military-grade P2P messaging.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:26813` | `military-grade` | `This module enforces strict military-grade security requirements with no fallbacks.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:26829` | `military-grade` | `Enforces military-grade security requirements with no fallbacks.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28040` | `nuclear command` | `NC3 (Nuclear Command, Control, and Communications) Subsystem` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28040` | `nuclear` | `NC3 (Nuclear Command, Control, and Communications) Subsystem` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28040` | `NC3` | `NC3 (Nuclear Command, Control, and Communications) Subsystem` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28042` | `military-grade` | `Military-Grade Emergency Action Message (EAM) & Permissive Action Link (PAL)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28046` | `NC3` | `- CJCSI 3265.01 (NC3 Command & Control Message Security)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28060` | `nuclear command` | `Base exception for all Nuclear Command and Control protocol violations.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28060` | `nuclear` | `Base exception for all Nuclear Command and Control protocol violations.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28231` | `NC3` | `Challenge issued by NC3 system to physically present hardware security tokens.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28313` | `sovereign` | `Generate sovereign ML-DSA-87 keypair for an authorized strategic officer.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28448` | `nuclear` | `Creates, dual-encrypts, and dual-signs a nuclear-grade Emergency Action Message.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28599` | `sovereign` | `or generates and provisions sovereign credentials if not present.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28637` | `NC3` | `Ensures baseline Strategic Command & Pentagon officer credentials exist for NC3 dual-custody operation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28646` | `NC3` | `Serializes an NC3 EAM dictionary with mandatory 1024-byte uniform block padding` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28656` | `NC3` | `Deserializes an NC3 EAM wire frame, decrypting AEAD envelope if keyed and` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:28664` | `military-grade` | `Production-ready network adversary resistance for military-grade P2P messaging.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:29724` | `military-grade` | `Operational Security Features for Military-Grade P2P Messaging` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:30866` | `NC3` | `Mitigates pre-auth DoS attacks on handshakes and ensures NC3/EAM release window availability.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:31563` | `maximum security` | `and memory protection extensions for maximum security isolation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:32136` | `maximum security` | `enhanced_security (bool, optional): Enable maximum security features including memory protection, integrity verificat...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:34599` | `military-grade` | `This function ensures that only approved military-grade algorithms are used:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:35507` | `military-grade` | `MILITARY-GRADE Hybrid Key Encapsulation Mechanism - NIST Level 5 Security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:35597` | `military-grade` | `MILITARY-GRADE HYBRID KEM IMPLEMENTATION` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:35604` | `military-grade` | `SECURITY UPGRADE: This class implements military-grade hybrid KEM` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:36284` | `military-grade` | `MILITARY-GRADE Hybrid Signature Scheme - NIST Level 5 Security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:36373` | `military-grade` | `MILITARY-GRADE FALCON-1024 SIGNATURE IMPLEMENTATION (FN-DSA track, FIPS 206 DRAFT / Level 5)` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:38423` | `military-grade` | `NIST FIPS 203/204/205 Compliant - Military-Grade Security` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:39821` | `sovereign` | `Automated Red-Team Adversarial Penetration Drill for Sovereign Military Defense Communications.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40032` | `military-grade` | `Implements reliable message delivery for military-grade P2P communications:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40566` | `military-grade` | `MASTER ORCHESTRATOR: FULL POTENTIAL MILITARY-GRADE BATTLE TEST FOR SECURE_P2.PY` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40572` | `tactical` | `5. High-Priority Tactical DEFCON-1 Flash Orders & Cryptographic ACK.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40601` | `tactical` | `Generate authentic tactical military telemetry dataset.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40617` | `tactical` | `Master Phase 5 DoD CSRMC Operations Phase & Tactical DDIL Resilience Mission Drill Harness.` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40618` | `mission-critical` | `Executes end-to-end operational verification across 5 mission-critical probes:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40667` | `tactical` | `Probe 2: Tactical DDIL Comms Disruption & Merkle-DAG Delta Reconciliation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40719` | `tactical` | `Master Phase 6 CJADC2 Tactical Data Fabric & Dynamic PQC Crypto-Agility Mission Drill Harness.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40720` | `mission-critical` | `Executes end-to-end operational verification across 5 mission-critical probes:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40822` | `tactical` | `tactical message dispatch and receipt, and clean cryptographic teardown.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:40839` | `classified` | `post-quantum mutual TLS 1.3 and Double Ratchet links, exchanges classified flash orders,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:41584` | `NC3` | `data: Bytes to sign (64-byte auth digests in the NC3 flow).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:42808` | `military-grade` | `Secure File Transfer - Military-Grade File Transfer with HMAC-SHA384 Chunk Verification` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:44365` | `military-grade` | `(DISABLED for Military-Grade Security - Fail Closed)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:45715` | `military-grade` | `Military-grade input validation class with strict validation and mandatory rejection.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:45717` | `military-grade` | `This class implements zero-compromise input validation according to military-grade` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:45890` | `military-grade` | `Military-grade cryptographic operations for hashed identifiers.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:45949` | `tactical` | `Create an ephemeral in-memory anonymous tactical identity (Zero disk storage).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:46012` | `military-grade` | `Save and encrypt user profile with military-grade hashing.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:46065` | `military-grade` | `peer management system with military-grade features.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:46198` | `tactical` | `anonymous: Whether to run in pure anonymous tactical mode (default: False)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:46227` | `maximum security` | `Enforce maximum security requirements with no fallbacks.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:46574` | `tactical` | `Enhanced startup flow with user management, anonymous tactical mode, and automatic login.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:47436` | `nuclear` | `Derives a deterministic 32-byte NC3 nuclear-grade war key from the authenticated hybrid root key.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:47436` | `NC3` | `Derives a deterministic 32-byte NC3 nuclear-grade war key from the authenticated hybrid root key.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:47445` | `NC3` | `Seals a chat message inside a full DoD Directive S-5210.41M / NC3 Emergency Action Message container.` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:47459` | `NC3` | `Verifies and unseals an incoming NC3 Emergency Action Message.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:47667` | `maximum security` | `security warnings and ensure maximum security for their application.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:48194` | `military-grade` | `Military-grade input validation class with strict validation and mandatory rejection.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:48196` | `military-grade` | `This class implements zero-compromise input validation according to military-grade` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:48369` | `military-grade` | `Military-grade cryptographic operations for hashed identifiers.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:48428` | `tactical` | `Create an ephemeral in-memory anonymous tactical identity (Zero disk storage).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:48491` | `military-grade` | `Save and encrypt user profile with military-grade hashing.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:48544` | `military-grade` | `peer management system with military-grade features.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:48677` | `tactical` | `anonymous: Whether to run in pure anonymous tactical mode (default: False)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:48706` | `maximum security` | `Enforce maximum security requirements with no fallbacks.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:49053` | `tactical` | `Enhanced startup flow with user management, anonymous tactical mode, and automatic login.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:49915` | `nuclear` | `Derives a deterministic 32-byte NC3 nuclear-grade war key from the authenticated hybrid root key.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:49915` | `NC3` | `Derives a deterministic 32-byte NC3 nuclear-grade war key from the authenticated hybrid root key.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:49924` | `NC3` | `Seals a chat message inside a full DoD Directive S-5210.41M / NC3 Emergency Action Message container.` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:49938` | `NC3` | `Verifies and unseals an incoming NC3 Emergency Action Message.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:50146` | `maximum security` | `security warnings and ensure maximum security for their application.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:50775` | `military-grade` | `Military-Grade Full-Project Security Diagnostics` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:52547` | `military-grade` | `Pre-deployment security validation script for the military-grade P2P messaging system.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:52651` | `military-grade` | `Military-Grade Side-Channel Resistance Module` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:52652` | `military-grade` | `Military-Grade Constant-Time Operations with Timing Verification` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:53650` | `tactical` | `Phase 5 Tactical DDIL Mesh resilience.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:53656` | `tactical` | `and tactical slash commands (/csrmc, /mesh, /flash, /quorum, /zeroize)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:53851` | `military-grade` | `Supply Chain Security System - Military-Grade Implementation` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55100` | `tactical` | `Tactical Network Cloaking & Overlay Routing Adapter for Contested Environments.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55102` | `tactical` | `Implements high-threat operational mode (P2P_TACTICAL_CLOAK=1 or --tactical-cloak):` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55103` | `tactical` | `- Enforces private tactical APN / WireGuard point-to-point overlay encapsulation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55110` | `tactical` | `Raised when an operation violates tactical network cloaking policy.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55119` | `tactical` | `True when tactical cloaking is enforced via environment or command-line.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55128` | `tactical` | `Check if destination IP is private, loopback, link-local, or tactical overlay.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55137` | `tactical` | `Validate that an outbound network destination complies with tactical cloaking.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55138` | `tactical` | `Under tactical cloaking, unencapsulated direct public IP connections are blocked.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55206` | `tactical` | `Simplex Tactical Data Diode with Forward Error Correction (FEC)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55210` | `tactical` | `- MIL-STD-188-220 & NATO STANAG 4586 (Tactical Data Telemetry)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55225` | `tactical` | `3. Cursor-on-Target (CoT) Tactical Telemetry:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55226` | `tactical` | `- Native MIL-STD tactical telemetry framing for blue-force tracking and command status.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55371` | `tactical` | `Standard NATO STANAG / US DoD tactical awareness message.` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55471` | `tactical` | `TACTICAL AIR-GAPPED KEY & PEER PROVISIONER (CNSA 2.0 / FIPS 140-3)` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55474` | `sovereign` | `fingerprint whitelists for sovereign, zero-trust military P2P nodes.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55474` | `zero-trust` | `fingerprint whitelists for sovereign, zero-trust military P2P nodes.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55523` | `tactical` | `Tactical Mesh Resilience for Disrupted, Disconnected, Intermittent, and Low-Bandwidth (DDIL) Environments.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55530` | `tactical` | `4. Adaptive packet pacing for low-bandwidth (< 64kbps) tactical military links.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55541` | `tactical` | `Pre-pinned Post-Quantum Keyring for Tactical DDIL Nodes (TETA Architecture).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55559` | `tactical` | `Register a tactical node's public key and return its 32-byte Key ID.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55596` | `tactical` | `Tactical Identity Cache (TIC) per Tactical Edge Triad Architecture (TETA 2025/2026).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55597` | `zero-trust` | `Caches identities, roles, and pre-attested credentials for zero-trust authorization offline.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55831` | `tactical` | `Tactical DDIL Mesh Router & Store-and-Forward Reconciler.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:55867` | `tactical` | `Update simulated or live link connectivity for a tactical peer.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:56956` | `zero-trust` | `Test 1: Zero-Trust Role-Based Access Control and Granular Authorization.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:57042` | `NC3` | `Test 9: Real Hardware Probing, Non-Silent Fallback Warnings, and NC3 Key Isolation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:58370` | `tactical` | `Tactical Network Cloaking & Overlay Routing Suite.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:58451` | `tactical` | `Tactical DDIL Mesh Store-and-Forward & Merkle Delta Reconciliation Suite.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:58540` | `tactical` | `MIL-STD-6090 Cursor-on-Target Tactical Messaging Suite.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:59794` | `military-grade` | `Military-Grade Threat Detection and Response System for Secure P2P` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:64062` | `maximum security` | `- Conservative parameters for maximum security margin` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:64631` | `military-grade` | `This script verifies all requirements for military-grade secure P2P communication` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:64663` | `military-grade` | `Production deployment verification for military-grade secure P2P system.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:64923` | `sovereign` | `Evaluates the Sovereign Military Communications Platform against the 7 Pillars of the` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:64929` | `tactical` | `5. Network & Environment: Tactical network cloaking, WireGuard UDP overlay, 0x direct public sockets` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:65042` | `zero-trust` | `Zero-Trust Authentication Engine - Strict Verification` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:65044` | `zero-trust` | `This module implements zero-trust authentication with session termination` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:65150` | `zero-trust` | `Zero-Trust Role-Based Access Control (RBAC) Engine.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:65202` | `zero-trust` | `Session states for zero-trust authentication` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:65226` | `zero-trust` | `Zero-Trust Authentication Engine with Strict Verification` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:65244` | `zero-trust` | `Initialize Zero-Trust Engine.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:66718` | `maximum security` | `Enforce maximum security - delegates to security module.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:69285` | `tactical` | `Toggle tactical cloaking and background traffic chaffing.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:70827` | `sovereign` | `Generates the complete 2027+ Sovereign Post-Quantum PKI hierarchy for the` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:70831` | `sovereign` | `1. Sovereign Root CA (Self-signed ML-DSA-87 + NIST P-521 anchor)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:70832` | `sovereign` | `2. Sovereign Tactical Issuing CA (Sub CA signed by Root CA)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:70832` | `tactical` | `2. Sovereign Tactical Issuing CA (Sub CA signed by Root CA)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:70833` | `tactical` | `3. Tactical Node Alpha Identity Certificate (Signed by Sub CA)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:70834` | `tactical` | `4. Tactical Node Bravo Identity Certificate (Signed by Sub CA)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:70887` | `classified` | `4. Radio Silence / RF Emission Discipline (WiFi / Bluetooth status on classified nodes)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:70938` | `classified` | `Verify RF Emission discipline / TEMPEST posture: wireless adapters disabled on classified nodes.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:71009` | `sovereign` | `Secure P2P Platform, establishing CNSA 2.0 sovereign root authority.` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:71455` | `maximum security` | `maximum security enforcement, and security manager initialization.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:71459` | `maximum security` | `- Maximum security enforcement with no fallbacks` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:71494` | `maximum security` | `- Maximum security enforcement` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:71532` | `maximum security` | `Enforce maximum security requirements with no fallbacks.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:72470` | `maximum security` | `security warnings and ensure maximum security for their application.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION.md:72518` | `tactical` | `Display DoD CSRMC Phase 5 continuous operations & DDIL tactical status.` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:426` | `tactical` | `#### `ByzantineQuorumEngine.register_command_node` (byzantine_mesh_consensus.py:113) — (self, node_id, public_key_byt...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:437` | `tactical` | `#### `ByzantineQuorumEngine.execute_approved_command` (byzantine_mesh_consensus.py:658) — (self, record) \| branches:...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:488` | `zero-trust` | `#### `CAExchange.add_authorized_fingerprint` (ca_services.py:587) — (self, fingerprint) \| branches:ifx1 calls:lower,...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:557` | `tactical` | `#### `AlliedCoalitionGateway.redact_and_package_for_coalition` (cjadc2_allied_gateway.py:241) — (self, payload_bytes,...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:597` | `tactical` | `#### `TacticalCoTEvent.to_compact_json` (cjadc2_tactical_cot.py:160) — (self) \| returns:1 — Serializes to bandwidth-...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:1430` | `tactical` | `### class `CanaryPilotDeployer` (deploy_canary_pilot.py:31) methods:8 — Orchestrates tactical canary node deployment ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:1434` | `tactical` | `#### `CanaryPilotDeployer._probe_tactical_cloaking` (deploy_canary_pilot.py:129) — (self) \| branches:ifx3,tryx2 call...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2470` | `maximum security` | `### class `MaximumSecurityError` (maximum_security_hardening.py:54) bases:Exception methods:1 — Exception raised when...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2478` | `maximum security` | `### class `MaximumSecurityHardening` (maximum_security_hardening.py:81) methods:20 — Maximum Security Hardening imple...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2479` | `maximum security` | `#### `MaximumSecurityHardening.__init__` (maximum_security_hardening.py:89) — (self) \| calls:system,lower,machine,in...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2497` | `maximum security` | `#### `MaximumSecurityHardening.enforce_maximum_security` (maximum_security_hardening.py:559) — (self) \| branches:ifx...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2499` | `maximum security` | `#### `enforce_maximum_security_or_fail` (maximum_security_hardening.py:630) — () \| branches:ifx1,tryx1 calls:Maximum...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2500` | `maximum security` | `#### `main` (maximum_security_hardening.py:654) — () \| branches:tryx1 calls:info,enforce_maximum_security_or_fail,ge...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2606` | `maximum security` | `#### `AdvancedSecurityEnhancements._enable_maximum_hardening` (memory_manager.py:1490) — (self) \| calls:info returns...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2884` | `nuclear command` | `### class `NC3SecurityError` (nc3_nuclear_command.py:46) bases:Exception methods:0 — Base exception for all Nuclear C...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2884` | `nuclear` | `### class `NC3SecurityError` (nc3_nuclear_command.py:46) bases:Exception methods:0 — Base exception for all Nuclear C...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2918` | `NC3` | `### class `HardwareChallenge` (nc3_nuclear_command.py:375) methods:2 — Challenge issued by NC3 system to physically p...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2930` | `sovereign` | `#### `NC3CommandController.generate_officer_credentials` (nc3_nuclear_command.py:475) — (officer_id, rank, duty_title...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2941` | `nuclear` | `#### `NC3CommandController.create_nuclear_eam` (nc3_nuclear_command.py:897) — (self, directive_code, target_command, ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2962` | `NC3` | `#### `provision_standard_tactical_officers` (nc3_nuclear_command.py:1517) — (officers_dir) \| calls:get_or_create_tac...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2963` | `NC3` | `#### `serialize_eam_wire` (nc3_nuclear_command.py:1540) — (eam_data, aead_key) \| branches:ifx4 calls:dumps,pack,toke...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:2964` | `NC3` | `#### `deserialize_eam_wire` (nc3_nuclear_command.py:1574) — (wire_bytes, aead_key) \| branches:ifx5,tryx2 calls:Value...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4155` | `tactical` | `#### `create_classified_payload` (run_full_potential_military_test.py:65) — () \| branches:forx1 calls:sha3_256,write...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4164` | `tactical` | `#### `Phase5OperationsMissionDrill._probe_2_ddil_disruption_reconciliation` (run_phase5_csrmc_operations_drill.py:173...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4722` | `tactical` | `#### `EnhancedUserManager.create_ephemeral_user` (secure_p2.py:1550) — (self, username, display_name) \| branches:ifx...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4750` | `maximum security` | `#### `SecureP2PChat._enforce_maximum_security` (secure_p2.py:2654) — (self) \| branches:ifx1,tryx2 calls:info,enforce...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4775` | `tactical` | `#### `SecureP2PChat._enhanced_startup_flow` (secure_p2.py:4072) — async (self) \| branches:ifx18,whilex1,tryx4 calls:...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4853` | `nuclear` | `#### `SecureP2PChat._get_or_derive_nc3_war_key` (secure_p2.py:11487) — (self) \| branches:ifx4,tryx1 calls:fromhex,HK...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4853` | `NC3` | `#### `SecureP2PChat._get_or_derive_nc3_war_key` (secure_p2.py:11487) — (self) \| branches:ifx4,tryx1 calls:fromhex,HK...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4854` | `NC3` | `#### `SecureP2PChat._create_nc3_chat_eam` (secure_p2.py:11527) — (self, text) \| calls:_ensure_nc3_tactical_officers,...` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4855` | `NC3` | `#### `SecureP2PChat._verify_and_unseal_nc3_msg` (secure_p2.py:11550) — (self, eam_data) \| branches:ifx7,tryx1 calls:...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4940` | `tactical` | `#### `EnhancedUserManager.create_ephemeral_user` (secure_p2p.py:1550) — (self, username, display_name) \| branches:if...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4968` | `maximum security` | `#### `SecureP2PChat._enforce_maximum_security` (secure_p2p.py:2654) — (self) \| branches:ifx1,tryx2 calls:info,enforc...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:4993` | `tactical` | `#### `SecureP2PChat._enhanced_startup_flow` (secure_p2p.py:4072) — async (self) \| branches:ifx18,whilex1,tryx4 calls...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5071` | `nuclear` | `#### `SecureP2PChat._get_or_derive_nc3_war_key` (secure_p2p.py:11487) — (self) \| branches:ifx4,tryx1 calls:fromhex,H...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5071` | `NC3` | `#### `SecureP2PChat._get_or_derive_nc3_war_key` (secure_p2p.py:11487) — (self) \| branches:ifx4,tryx1 calls:fromhex,H...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5072` | `NC3` | `#### `SecureP2PChat._create_nc3_chat_eam` (secure_p2p.py:11527) — (self, text) \| calls:_ensure_nc3_tactical_officers...` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5073` | `NC3` | `#### `SecureP2PChat._verify_and_unseal_nc3_msg` (secure_p2p.py:11550) — (self, eam_data) \| branches:ifx7,tryx1 calls...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5647` | `tactical` | `### class `TacticalCloakViolation` (tactical_cloaking_router.py:18) bases:? methods:0 — Raised when an operation viol...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5648` | `tactical` | `#### `tactical_cloak_enabled` (tactical_cloaking_router.py:22) — () \| calls:lower returns:1 — True when tactical clo...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5649` | `tactical` | `#### `is_private_or_loopback` (tactical_cloaking_router.py:28) — (host) \| branches:ifx1,tryx1 calls:ip_address,endsw...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5650` | `tactical` | `#### `validate_outbound_destination` (tactical_cloaking_router.py:45) — (host, port) \| branches:ifx2 calls:tactical_...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5705` | `tactical` | `### class `TacticalKeyring` (tactical_mesh_ddil.py:50) methods:4 — Pre-pinned Post-Quantum Keyring for Tactical DDIL ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5707` | `tactical` | `#### `TacticalKeyring.register_peer_key` (tactical_mesh_ddil.py:58) — (self, node_id, pubkey_bytes) \| calls:sha3_256...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5714` | `tactical` | `### class `TacticalIdentityCache` (tactical_mesh_ddil.py:91) methods:3 — Tactical Identity Cache (TIC) per Tactical E...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5745` | `tactical` | `### class `DDILNodeMesh` (tactical_mesh_ddil.py:446) methods:9 — Tactical DDIL Mesh Router & Store-and-Forward Reconc...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5749` | `tactical` | `#### `DDILNodeMesh.set_peer_connectivity` (tactical_mesh_ddil.py:490) — (self, peer_id, connected) \| branches:ifx1 c...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5898` | `zero-trust` | `### class `TestZeroTrustRBAC` (test_2028_national_security_remediations.py:55) bases:TestCase methods:5 — Test 1: Zer...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5900` | `NC3` | `#### `TestZeroTrustRBAC.test_operator_least_privilege` (test_2028_national_security_remediations.py:61) — (self) \| c...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5901` | `NC3` | `#### `TestZeroTrustRBAC.test_commander_privileges` (test_2028_national_security_remediations.py:76) — (self) \| calls...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5937` | `NC3` | `### class `TestRealHardwareAndNonSilentFallback` (test_2028_national_security_remediations.py:454) bases:TestCase met...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:5940` | `NC3` | `#### `TestRealHardwareAndNonSilentFallback.test_nc3_secret_key_serialization_rejected_in_production` (test_2028_natio...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:6060` | `tactical` | `#### `TestDefensiveAuditRemediations.test_tactical_key_provisioner_fail_closed_and_210k_pbkdf2` (test_defensive_audit...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:6376` | `nuclear` | `#### `TestNC3NuclearCommandReadiness.test_07_full_double_envelope_transmission_over_rust_data_plane` (test_nc3_nuclea...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:6424` | `NC3` | `#### `test_nc3_two_terminal_live_eam_transfer` (test_nc3_two_terminal_live_transfer.py:377) — () \| calls:run_live_nc...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:6435` | `tactical` | `#### `TestNetworkEndpointDiscovery.test_air_gap_mode_suppresses_stun` (test_network_endpoint_discovery.py:110) — (sel...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:6635` | `tactical` | `### class `TestTacticalCloakingRouter` (test_phase4_ato_redteam_siem.py:189) methods:2 — Tactical Network Cloaking & ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:6636` | `tactical` | `#### `TestTacticalCloakingRouter.test_tactical_cloaking_blocking_public_destination` (test_phase4_ato_redteam_siem.py...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:6670` | `tactical` | `### class `TestTacticalMeshDDILSuite` (test_phase5_csrmc_ddil_operations.py:98) methods:4 — Tactical DDIL Mesh Store-...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:6711` | `tactical` | `### class `TestTacticalCoTSuite` (test_phase6_cjadc2_data_fabric.py:189) methods:3 — MIL-STD-6090 Cursor-on-Target Ta...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:6883` | `NC3` | `#### `TestProductionTier7CSPRNGCompleteAudit.test_04_nc3_wire_padding_and_nonce` (test_production_tier7_csprng_comple...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:6968` | `NC3` | `#### `TestSecurityAuditRemediations.test_finding_3_2_nc3_replay_journal_persistence` (test_security_audit_remediation...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:7013` | `tactical` | `#### `TestTacticalDataDiode.test_10_e2e_simplex_cot_telemetry_transmission` (test_tactical_data_diode.py:244) — (self...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:7719` | `zero-trust` | `### class `RBACPolicyEngine` (zero_trust_engine.py:167) methods:5 — Zero-Trust Role-Based Access Control (RBAC) Engine.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:7726` | `zero-trust` | `### class `SessionState` (zero_trust_engine.py:265) bases:Enum methods:0 — Session states for zero-trust authentication` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:7733` | `zero-trust` | `### class `ZeroTrustEngine` (zero_trust_engine.py:304) methods:21 — Zero-Trust Authentication Engine with Strict Veri...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:7734` | `zero-trust` | `#### `ZeroTrustEngine.__init__` (zero_trust_engine.py:318) — (self, identity_key, signing_key) \| branches:ifx1,tryx2...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:7874` | `maximum security` | `#### `SecureP2PChat._enforce_maximum_security` (core/orchestrator.py:810) — (self) \| branches:tryx1 calls:enforce_ma...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:8150` | `tactical` | `#### `CommandProcessor._toggle_tactical_cloak` (messaging/commands.py:468) — (self) \| branches:ifx1,tryx1 calls:tact...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:8310` | `classified` | `#### `HostHardeningVerifier.check_radio_silence` (scripts/verify_host_hardening.py:270) — (self) \| branches:ifx5,for...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:8376` | `maximum security` | `#### `SecurityHardening.enforce_maximum_security` (security/hardening.py:212) — (self) \| branches:tryx1 calls:info,e...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:8503` | `tactical` | `#### `DisplayManager._display_csrmc_phase5_status` (ui/display.py:470) — (self) \| branches:tryx1 calls:get_csrmc_ope...` | (b) Standard Identifier | KEEP |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:9378` | `sovereign` | `\| `P2P_NODE_ID` \| `remote_siem_forwarder.py` \| `__init__` \| `default 'sovereign-node-01'` \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:9906` | `sovereign` | `- `tls_channel_manager.py` `__init__` — `f"Public cloud OAuth provider '{self.provider_name}' prohibited in sovereign...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:9907` | `sovereign` | `- `tls_channel_manager.py` `start_device_flow` — `f"OAuth device flow for '{self.provider_name}' is blocked in sovere...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:10954` | `NC3` | `- `nc3_nuclear_command.py` `to_dict` — `'MILITARY FATAL: Serialization of NC3 secret signing keys to dictionaries/JSO...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:10957` | `zero-trust` | `- `nc3_nuclear_command.py` `verify_and_decrypt_nuclear_eam` — `f"EAM rejected: sender peer identity is in unverified ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:11558` | `tactical` | `- `tactical_cloaking_router.py` `validate_outbound_destination` — `f'[TACTICAL CLOAK VIOLATION] Direct unencapsulated...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:11935` | `classified` | `- Not certified, accredited, or authorized to carry any classified or` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/SYSTEM_SECURITY_DOCUMENTATION_VOL_C.md:11941` | `quantum-proof` | `- Not quantum-proof in any absolute sense: it is resistant under stated,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:2` | `sovereign` | `## Sovereign Transmit Protocol Specification and Operational Doctrine` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:3` | `zero-trust` | `### High-Assurance Zero-Trust Transport Architecture for National Security Systems` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:20` | `sovereign` | `This technical manual defines the protocol architecture, cryptographic state machines, and hardware gating boundaries...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:25` | `top secret` | `- **NSA CNSA Suite 2.0 Mandate (2022/2024):** Algorithms for NSS protecting information up to TOP SECRET // SCI.` | (b) Standard Identifier | KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:35` | `nuclear command` | `- **DoD S-5210.41M / CJCSI 3265.01:** Nuclear Command and Control (NC3) Two-Person Integrity (TPI) Controls.` | (b) Standard Identifier | KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:35` | `nuclear` | `- **DoD S-5210.41M / CJCSI 3265.01:** Nuclear Command and Control (NC3) Two-Person Integrity (TPI) Controls.` | (b) Standard Identifier | KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:35` | `NC3` | `- **DoD S-5210.41M / CJCSI 3265.01:** Nuclear Command and Control (NC3) Two-Person Integrity (TPI) Controls.` | (b) Standard Identifier | KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:56` | `tactical` | `\| [1] Tactical Edge \| Direct Raw UDP / IPv6       \| Noise-XXhfs (ML-KEM-1024      \| TPM 2.0 PCR Quote        \| C...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:58` | `tactical` | `\|     (Vehicular)   \| Constant 50ms pacing        \| AES-256-GCM / 128-bit tag     \| Monotonic NV Counter     \| T...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:64` | `top secret` | `\| [3] Cross-Domain  \| Simplex Optical Diode       \| Unidirectional Push           \| Physical Single-Fiber    \| T...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:68` | `top secret` | `\| [4] Air-Gapped    \| Cryptographic QR Burst      \| Offline Ephemeral Ratchet     \| Air-gapped Workstation   \| T...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:70` | `SCIF` | `\|     (SCIF / EOC)  \| Sealed Envelope Format      \| Hardware Root CA PKI (3-of-5) \| Zero Network Interface   \| D...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:72` | `sovereign` | `\| [5] Joint Edge    \| Allied Gateway Protocol     \| Sovereign Group Ratchet (TPI) \| FIPS 140-3 Cryptographic \| M...` | (b) Standard Identifier | KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:77` | `NC3` | `\|     Command (NC3) \| Out-of-Band Dual-Channel    \| Dual ML-DSA-87 Cryptographic  \| Independent Operator     \| E...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:84` | `tactical` | `#### Topology 1: Tactical Edge DDIL Radio (Vehicular / Soldier Dismounted)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:85` | `tactical` | `- **Where Used:** Forward tactical operating bases, unmanned systems, vehicular ad-hoc networks, high-frequency tacti...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:95` | `classified` | `- **Where Used:** Interfaces between classified RED processing enclaves and unclassified BLACK transmission channels.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:99` | `SCIF` | `#### Topology 4: Air-Gapped Command Post (SCIF / Bunker Operations)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:100` | `SCIF` | `- **Where Used:** Sensitive Compartmented Information Facilities (SCIF) with complete physical air gaps.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:106` | `tactical` | `- **Transport Behavior:** Translates MIL-STD-6090 Cursor-on-Target (CoT) tactical tactical data into post-quantum enc...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:109` | `nuclear command` | `#### Topology 6: Strategic Nuclear Command and Control (NC3)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:109` | `nuclear` | `#### Topology 6: Strategic Nuclear Command and Control (NC3)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:109` | `NC3` | `#### Topology 6: Strategic Nuclear Command and Control (NC3)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:126` | `tactical` | `\| Python Master Orchestrator  \| `secure_transmit_2027.py`          \| Central tactical CLI & daemon  \| Coordinates...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:168` | `sovereign` | `\| Sovereign Group Ratchet     \| `sovereign_group_ratchet.py`       \| Multi-party tactical group     \| Dynamic epo...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:168` | `tactical` | `\| Sovereign Group Ratchet     \| `sovereign_group_ratchet.py`       \| Multi-party tactical group     \| Dynamic epo...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:174` | `nuclear command` | `\| Nuclear Command & Control   \| `nc3_nuclear_command.py`           \| DoD S-5210.41M Two-Person      \| Dual-termin...` | (b) Standard Identifier | KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:174` | `nuclear` | `\| Nuclear Command & Control   \| `nc3_nuclear_command.py`           \| DoD S-5210.41M Two-Person      \| Dual-termin...` | (b) Standard Identifier | KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:175` | `NC3` | `\| (NC3 Engine)                \| [`nc3_nuclear_command.py:L1-L130`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/nc3...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:279` | `classified` | `1. **Simple Security Property (No Read Up):** A system running at classification level $L_1$ cannot read or decrypt i...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:288` | `top secret` | `- `TOP SECRET`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:289` | `top secret` | `- `TOP SECRET // SCI // NOFORN`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:291` | `top secret` | `Compartment keys are derived via standard **SP 800-56C HKDF-SHA3-512** in [`cjadc2_cross_domain_guard.py:L231-L255`](...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:293` | `tactical` | `### 8.3 Simplex Optical Tactical Data Diode FEC` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:302` | `sovereign` | `### 9.1 Sovereign Group Ratchet & Post-Compromise Security (PCS)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:303` | `sovereign` | `Tactical talkgroups use the Sovereign Group Ratchet in [`sovereign_group_ratchet.py`](file:///d:/code/Main_projects/p...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:303` | `tactical` | `Tactical talkgroups use the Sovereign Group Ratchet in [`sovereign_group_ratchet.py`](file:///d:/code/Main_projects/p...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:305` | `tactical` | `- **Break-in Recovery:** If an adversary compromises a tactical handset's ephemeral memory, the next epoch rotation i...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:309` | `nuclear command` | `- Nuclear Command, Control, and Communications (NC3) and critical tactical release actions require **Two-Person Integ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:309` | `nuclear` | `- Nuclear Command, Control, and Communications (NC3) and critical tactical release actions require **Two-Person Integ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:309` | `NC3` | `- Nuclear Command, Control, and Communications (NC3) and critical tactical release actions require **Two-Person Integ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/TECHNICAL_MANUAL_ST2027_TACTICAL_COMMUNICATIONS.md:309` | `tactical` | `- Nuclear Command, Control, and Communications (NC3) and critical tactical release actions require **Two-Person Integ...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/airgap_runbook.md:98` | `destroyer` | `%USERPROFILE%\.destroyer-st2027\offline-keys\` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/airgap_runbook.md:111` | `destroyer` | `export SBOM_SIGNING_KEY="$HOME/.destroyer-st2027/offline-keys/sbom_mldsa87_signer.sk"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/airgap_runbook.md:113` | `destroyer` | `export P2P_CRL_SIGNING_KEY="$HOME/.destroyer-st2027/offline-keys/crl_mldsa87_signer.sk"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/airgap_runbook.md:114` | `destroyer` | `export P2P_CA_KEY_PATH="$HOME/.destroyer-st2027/offline-keys/military_root_ca.pem"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:166` | `destroyer` | `\| `destroyer.py` \| Python \| 504 \| DESTROYER ST2027 — [restricted-term] DEFENSE COMMAND CENTER \| `orchestrator_ap...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:168` | `destroyer` | `\| `destroyer_tactical_p2p.py` \| Python \| 37 \| DESTROYER STRATEGIC P2P: [restricted-term] [restricted-term] COMMUN...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:171` | `tactical` | `\| `docs/CONOPS_TACTICAL_DEPLOYMENT.md` \| Markdown \| 376 \| Concept of Operations (CONOPS): [restricted-term] [rest...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:177` | `destroyer` | `\| `docs/FORENSIC_SECURITY_AUDIT_2026_10_24_REMEDIATION_PLAN.md` \| Markdown \| 37 \| Destroyer-ST2027 Security Remed...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:178` | `destroyer` | `\| `docs/FORENSIC_SECURITY_AUDIT_3_REMEDIATION.md` \| Markdown \| 114 \| Destroyer-ST2027: Third Independent Forensic...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:179` | `destroyer` | `\| `docs/FORENSIC_SECURITY_AUDIT_4_REMEDIATION.md` \| Markdown \| 140 \| Destroyer-ST2027: Fourth Forensic Security A...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:187` | `NC3` | `\| `docs/MILITARY_NC3_DEPLOYMENT_GUIDE.md` \| Markdown \| 169 \| [restricted-term] [restricted-term] NC3 Deployment &...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:202` | `destroyer` | `\| `docs/ST2027_SPECIFICATION.md` \| Markdown \| 175 \| Destroyer-ST2027 Protocol Specification: High-Assurance Post-...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:273` | `destroyer` | `\| `docs/audit/release/RELEASE_CANDIDATE.md` \| Markdown \| 45 \| Release Candidate Specification: Destroyer-ST2027 V...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:349` | `maximum security` | `\| `maximum_security_hardening.py` \| Python \| 677 \| Maximum Security Hardening Module \| `security_framework` \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:413` | `tactical` | `\| `rust_data_plane/src/cot.rs` \| Rust \| 277 \| Cursor-on-Target tactical data message serialization \| `rust_data_...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:430` | `NC3` | `\| `rust_data_plane/src/nc3.rs` \| Rust \| 294 \| Dual-officer two-person integrity verification logic \| `rust_data_...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:444` | `zero-trust` | `\| `rust_data_plane/src/zero_trust.rs` \| Rust \| 423 \| Zero-Trust Continuous Verification & Risk Scoring Engine. \|...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:529` | `tactical` | `\| `tactical_data_diode.py` \| Python \| 674 \| Simplex Tactical Data Diode with Forward Error Correction (FEC) \| `m...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:535` | `destroyer` | `\| `tactical_web/index.html` \| HTML \| 682 \| HTML document; title: Destroyer Tactical P2P — [restricted-term] Defen...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:535` | `tactical` | `\| `tactical_web/index.html` \| HTML \| 682 \| HTML document; title: Destroyer Tactical P2P — [restricted-term] Defen...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:568` | `NC3` | `\| `tests/test_defensive_nc3_audit.py` \| Python \| 274 \| Zero-Gap Defensive Security Audit Suite for Direct-P2P [re...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:602` | `NC3` | `\| `tests/test_nc3_cnsa_cipher.py` \| Python \| 119 \| NC3 PAL bulk cipher: AES-256-GCM seals, legacy ChaCha verifies...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:603` | `NC3` | `\| `tests/test_nc3_nuclear_command_readiness.py` \| Python \| 374 \| NC3 ([restricted-term] Command, Control, and Com...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:605` | `NC3` | `\| `tests/test_nc3_two_person_integrity.py` \| Python \| 414 \| Test Suite: NC3 / PAL Two-Person Integrity (TPI) & Du...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:606` | `NC3` | `\| `tests/test_nc3_two_terminal_live_transfer.py` \| Python \| 399 \| NC3 TWO-TERMINAL LIVE INTEGRATION TEST (SECURE_...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:627` | `NC3` | `\| `tests/test_pkcs11_token_provider.py` \| Python \| 115 \| Tests for PKCS#11 hardware token backend and software si...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:646` | `tactical` | `\| `tests/test_resilient_ddil.py` \| Python \| 126 \| DDIL resilient-communication gates (Tier-1 tactical credibility...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:666` | `tactical` | `\| `tests/test_tactical_data_diode.py` \| Python \| 277 \| Test Suite: Simplex Tactical Data Diode & Forward Error Co...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:667` | `tactical` | `\| `tests/test_tactical_operations_suite.py` \| Python \| 154 \| Unit and Integration Test Suite for Real [restricted...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:668` | `tactical` | `\| `tests/test_tactical_replay.py` \| Python \| 78 \| Behavioral tests for tactical message anti-replay protection. \...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:669` | `tactical` | `\| `tests/test_tactical_web_console.py` \| Python \| 162 \| Unit tests for Tactical Web Command Center API handlers. ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/00_inventory.md:726` | `zero-trust` | `\| `zero_trust_engine.py` \| Python \| 850 \| Zero-Trust Authentication Engine - Strict Verification \| `audit_threat...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/BASELINE.md:6` | `destroyer` | `**Repository:** `Destroyer-ST2027` (`https://github.com/Destroyer-official/Destroyer-ST2027`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/BASELINE.md:28` | `destroyer` | `\| `origin` \| `https://github.com/Destroyer-official/Destroyer-ST2027.git` \| `https://github.com/Destroyer-official...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/BASELINE.md:29` | `destroyer` | `\| `st2027` \| `https://github.com/Destroyer-official/Destroyer-ST2027.git` \| `https://github.com/Destroyer-official...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/BASELINE.md:30` | `destroyer` | `\| `backup` \| `https://github.com/Destroyer-official/secure_p2p_backups.git` \| `https://github.com/Destroyer-offici...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/BASELINE.md:97` | `NC3` | `- Step 5: NC3 strict keyword safety gate enforcement (blocked unauthorised directives) — PASS` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/BASELINE.md:114` | `NC3` | `5. `src/pipeline.rs:224`: `clippy::collapsible-if` on NC3 safety gate check.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/CHANGELOG.md:5` | `destroyer` | `**Project:** Destroyer-ST2027` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/CHANGELOG.md:23` | `destroyer` | `\| **CHG-11** \| [`secure_p2p.py:61-75`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/secure_p2p.py#L61-L75) \| Proto...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/CHANGELOG.md:29` | `NC3` | `\| **CHG-17** \| [`rust_data_plane/src/ffi.rs`](file:///D:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/src/ffi....` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:7` | `destroyer` | `**Baseline Repository:** `Destroyer-ST2027` (`https://github.com/Destroyer-official/Destroyer-ST2027.git`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:82` | `tactical` | `- *Baseline Defect:* Flat pairwise sender-key ratchets scaled $O(N)$ across multi-party tactical networks, creating p...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:85` | `tactical` | `- Each tactical node occupies a leaf in a left-balanced binary tree.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:103` | `tactical` | `- *Baseline Defect:* Tactical web console lacked strict Content-Security-Policy headers, allowing potential UI redres...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:125` | `tactical` | `- *Baseline Defect:* Lack of pre-loaded genuine vendor Endorsement Key (EK) root certificates prevented fail-closed p...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:130` | `tactical` | `2. **Hardware-Anchored 3-of-5 Threshold PKI:** Implemented in `rust_data_plane/src/threshold_pki.rs` requiring at lea...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:131` | `NC3` | `3. **Dual-Custody Command & Control (NC3) Directives:** Emergency Action Messages (EAM) and cryptographic zeroization...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:142` | `tactical` | `- *Baseline Defect:* Tactical UDP datagrams revealed packet boundaries, timing cadences, and routing metadata suscept...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:145` | `mission-critical` | `2. **Constant-Rate Chaff Traffic Pacing:** Implemented 50ms interval dummy frame pacing in [`network_adversary_resist...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:147` | `tactical` | `4. **Systematic Cauchy Reed-Solomon Forward Error Correction (FEC):** Configured $(K=8, M=4)$ Cauchy distribution mat...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DEFENSE_SCORECARD_100_IMPLEMENTATION_PLAN.md:210` | `tactical` | `3. **Air-Gapped Deployment Package:** Turnkey distribution scripts capable of offline installation and bootstrapping ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DOCUMENTATION_DISCREPANCIES.md:6` | `destroyer` | `**Project:** Destroyer-ST2027` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DOCUMENTATION_DISCREPANCIES.md:17` | `destroyer` | `\| **Monolith vs. Modular Package** \| Architecture diagrams treat `destroyer.py` and `core/orchestrator.py` as prima...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/DOCUMENTATION_DISCREPANCIES.md:20` | `NC3` | `\| **NC3 Safety Gate Interception** \| Chat interface implies arbitrary text messaging between authenticated nodes. \...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/FINDINGS.md:30` | `NC3` | `- `rust_data_plane/src/pipeline.rs:224`: `clippy::collapsible-if` on nested NC3 safety check.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/KNOWN_LIMITATIONS.md:6` | `destroyer` | `**Project:** Destroyer-ST2027` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/PROGRESS.md:34` | `NC3` | `\| 08 \| `rust_data_plane` \| `rust_data_plane/`, `ts_rt/` (Cargo.toml, src/*.rs: cot, doc_transfer, fragment, group_...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/PROGRESS.md:41` | `destroyer` | `\| 15 \| `orchestrator_application` \| `secure_p2p.py`, `destroyer.py`, `base.py`, `core/` \| IN_PROGRESS \| `docs/au...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/SECURITY_REVIEW.md:6` | `destroyer` | `**Project:** Destroyer-ST2027` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/WORKSPACE_INVENTORY.md:19` | `NC3` | `\| **Product Source (Untracked)** \| 8 \| 3,142 \| Review Required \| Newly authored Rust modules (`cot.rs`, `doc_tra...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/WORKSPACE_INVENTORY.md:79` | `NC3` | `\| `rust_data_plane/src/nc3.rs` \| Untracked Code \| NC3 strict keyword safety gate \| Low \| Pending human review \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/WORKSPACE_INVENTORY.md:81` | `tactical` | `\| `rust_data_plane/src/ptt.rs` \| Untracked Code \| Push-To-Talk tactical voice telemetry \| Low \| Pending human re...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/claims/audit_threat_monitoring_claims.md:11` | `zero-trust` | `\| ATM-05 \| Access decisions evaluate dynamic trust scores based on device attestation freshness, link latency, and ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/claims/tactical_command_cjadc2_claims.md:7` | `NC3` | `\| TAC-01 \| Emergency Action Messages (EAM) and critical directives require dual-custody authorization from two dist...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/claims/tactical_command_cjadc2_claims.md:10` | `classified` | `\| TAC-04 \| Messages crossing security classification domain boundaries undergo Bell-LaPadula access control evaluat...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/claims/transport_anonymity_claims.md:9` | `tactical` | `\| ANO-03 \| Tactical cloaking blocks direct unencapsulated connections to public IP addresses unless routed through ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/command_log.md:27` | `destroyer` | `\| CMD-16 \| `repo_root` \| `git checkout -b audit/destroyer-st2027-verified-fixes` \| 0 \| Dedicated remediation rel...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/command_log.md:29` | `destroyer` | `\| CMD-18 \| `repo_root` \| `git push -u origin audit/destroyer-st2027-verified-fixes` \| 0 \| Published remediation ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/command_log.md:32` | `destroyer` | `\| CMD-21 \| `repo_root` \| `git push origin audit/destroyer-st2027-verified-fixes` \| 0 \| Remote branch updated wit...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/command_log.md:33` | `destroyer` | `\| CMD-22 \| `repo_root` \| `git ls-remote origin refs/heads/audit/destroyer-st2027-verified-fixes` \| 0 \| Confirmed...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/command_log.md:42` | `destroyer` | `\| CMD-31 \| `repo_root` \| `gh pr create --base main --head audit/destroyer-st2027-verified-fixes ...` \| 0 \| Creat...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/compliance_artifacts_audit.md:66` | `zero-trust` | `- **AC (Access Control):** Zero-trust mutual certificate authentication.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/documentation_claims_matrix.md:14` | `tactical` | `\| **Operational & CONOPS Guides** \| 8 \| 4,250 \| Tactical deployment procedures, airgap runbooks, hardware guides. \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/DEF-05.md:32` | `tactical` | `- Potential unbounded heap allocation in constrained tactical edge environments.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-01_to_F-04.md:4` | `destroyer` | `**Audit Scope**: Remediation and verification of four findings reported in external forensic security audit against D...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-01_to_F-04.md:93` | `destroyer` | `Under the repository authority boundaries (agent is restricted from altering GitHub repository settings directly), th...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:4` | `destroyer` | `This document records the forensic analysis, implementation remediations, and verification evidence for audit finding...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:11` | `NC3` | `\| **F-08** \| High Assurance \| `secure_p2p.py` (NC3 reader & Tactical node) \| Remediated (Two-Person Rule enforcem...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:11` | `tactical` | `\| **F-08** \| High Assurance \| `secure_p2p.py` (NC3 reader & Tactical node) \| Remediated (Two-Person Rule enforcem...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:13` | `destroyer` | `\| **F-10** \| Medium \| `destroyer.py` (Hardware & crypto probe) \| Remediated (CMVP status decoupled from binary) \...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:91` | `NC3` | `## F-08: Tactical EAM / NC3 Two-Person Rule Authorization` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:91` | `tactical` | `## F-08: Tactical EAM / NC3 Two-Person Rule Authorization` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:94` | `NC3` | `In `AutonomousSecureP2P` / `SecureP2PChat` lines 13903–13914, received NC3 Emergency Action Messages (EAM) displayed ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:102` | `NC3` | `print(f"\n[{name} NC3 SECURITY VIOLATION] Directive dropped: Two-Person Rule unverified ({two_person})")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:106` | `NC3` | `print(f"\n[{name} NC3 SECURITY VIOLATION] Directive dropped: Temporal expiration guard (expired)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:109` | `tactical` | `2. **Tactical Node Custodian Constraints**: In `TacticalP2PNode`, enforced:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:112` | `NC3` | `- Rejection of malformed or unparseable NC3 frames fail-closed without displaying raw data.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/F-05_to_F-10.md:140` | `destroyer` | ``destroyer.py:74` previously reported:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/findings/NOM-01_to_NOM-10.md:21` | `NC3` | `\| NOM-06 \| `tactical_command_cjadc2` \| 85 \| Directive log string \| Diagnostic log message for EAMs \| Replace wi...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/index.md:20` | `NC3` | `\| **Product Modules (Untracked)** \| 8 \| 3,142 \| Newly authored Rust modules (`cot.rs`, `doc_transfer.rs`, `fragme...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/authority_boundary.md:11` | `destroyer` | `The Destroyer-ST2027 codebase enforces a strict separation of concerns between the **Signaling / Control Plane (Pytho...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/authority_boundary.md:17` | `destroyer` | `\|  - CLI Orchestration (destroyer.py, secure_p2p.py)                      \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/host_runtime_attestation.md:171` | `TEMPEST shielding` | `\| `P2P_TEMPEST_REGISTRY` \| `ts_hw_layer.py:250` \| None \| Filepath to TEMPEST shielding compliance registry. \|` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/key_management_pki.md:29` | `tactical` | `The `key_management_pki` module provides key custody, platform hardware abstraction (TPM 2.0 / Windows CNG / PKCS#11)...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/key_management_pki.md:283` | `tactical` | `\| `P2P_TACTICAL_KEY_PW` \| `tactical_key_provisioner.py:52` \| None \| Pre-shared passphrase for tactical credential...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/mesh_ddil_networking.md:35` | `tactical` | `- `CursorOnTargetEvent` (`:340`): Parses and serializes tactical Cursor-on-Target (CoT) XML event envelopes.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/mesh_ddil_networking.md:236` | `tactical` | `- Does `tactical_data_diode.py` adapt shard sizes dynamically when operating over link layers with smaller MTU constr...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/messaging_file_transfer.md:79` | `tactical` | `- Tactical chat slash command router: verified in `tests/test_production_tier4_tactical_commands.py` (20 tests).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/orchestrator_application.md:4` | `destroyer` | `The `orchestrator_application` module coordinates runtime execution, application entry points, handshake state machin...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/orchestrator_application.md:93` | `NC3` | `- Simulated Command Surfaces: Commands `/eam`, `/ptt`, and `/nc3-verify` are test stubs and are disabled fail-closed ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/orchestrator_application.md:104` | `destroyer` | `- Can `secure_p2p.py` be deprecated in favor of `core/orchestrator.py` and `destroyer.py` once all test suites migrat...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/rust_data_plane.md:65` | `zero-trust` | `- `get_zero_trust_engine()` (`:130`): Returns native Zero-Trust policy engine.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/rust_data_plane.md:170` | `zero-trust` | `- Validates ACD engine replay quarantine, tamper immediate isolation, cookie gate PoW challenge solving, memory guard...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/system_hardening_integrity.md:40` | `tactical` | `- Magic Bytes: 4 bytes `b"STDI"` (Simplex Tactical Diode Ingest).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/tactical_command_cjadc2.md:11` | `NC3` | `- Associated security enforcement: Dual-custody authorization logic implemented in [critical_release.py](file:///d:/c...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/tactical_command_cjadc2.md:79` | `NC3` | `### 2.4 Dual-Custody Authorization: `critical_release.py` and `rust_data_plane/src/nc3.rs`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/tactical_command_cjadc2.md:88` | `NC3` | `- Native Two-Person Rule Protocol in Rust ([`rust_data_plane/src/nc3.rs`](file:///d:/code/Main_projects/p2p/p2p_6_1-2...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/tactical_command_cjadc2.md:89` | `NC3` | `- Cryptographic domain separator: `NC3_EAM_DOMAIN = b"DESTROYER-ST2027-NC3-EAM"` (`:13`).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/tactical_command_cjadc2.md:89` | `destroyer` | `- Cryptographic domain separator: `NC3_EAM_DOMAIN = b"DESTROYER-ST2027-NC3-EAM"` (`:13`).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/tactical_command_cjadc2.md:139` | `NC3` | `- In native Rust data plane ([rust_data_plane/src/nc3.rs:16, 200-208](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ru...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/tactical_command_cjadc2.md:143` | `NC3` | `- Rust: `verify_two_person_rule` ([rust_data_plane/src/nc3.rs:83-91](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rus...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/tactical_command_cjadc2.md:147` | `NC3` | `3. **Wire Format of Native EAM Directives ([rust_data_plane/src/nc3.rs:103-145](file:///d:/code/Main_projects/p2p/p2p...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/tactical_command_cjadc2.md:230` | `NC3` | ``rust_data_plane::nc3::verify_two_person_rule()` returns `Err(CoreError::AuthRequired)` when identical public keys ar...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/tls_channel.md:187` | `tactical` | `- `_validate_certificate_with_dane` (`:4904`) requires an active DNSSEC resolver. In air-gapped or tactical networks ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/transport_anonymity.md:322` | `top secret` | `- `transport_anonymity.py:3, 685`: Comments and string constants include prohibited words (e.g. `"TOP SECRET transmis...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/transport_anonymity.md:322` | `destroyer` | `- `transport_anonymity.py:3, 685`: Comments and string constants include prohibited words (e.g. `"TOP SECRET transmis...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/ui_presentation.md:343` | `tactical` | `- `ui/display.py:451` outputs `"[DEFENSE] DOD CSRMC PHASE 5 OPERATIONS & TACTICAL DDIL RESILIENCE"`.` | (b) Standard Identifier | KEEP |
| `docs/audit/modules/ui_presentation.md:344` | `tactical` | `- `ui/display.py:457` outputs `"[NETWORK] CJADC2 TACTICAL DATA FABRIC & CRYPTO-AGILITY"`.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/ui_presentation.md:346` | `sovereign` | `- `tactical_web/index.html:16` outputs `"TOP SECRET // CNSA SUITE 2.0 // NOFORN // SOVEREIGN MILITARY DATA PLANE"`.` | (b) Standard Identifier | KEEP |
| `docs/audit/modules/ui_presentation.md:346` | `top secret` | `- `tactical_web/index.html:16` outputs `"TOP SECRET // CNSA SUITE 2.0 // NOFORN // SOVEREIGN MILITARY DATA PLANE"`.` | (b) Standard Identifier | KEEP |
| `docs/audit/modules/ui_presentation.md:347` | `destroyer` | `- `tactical_web/index.html:29` outputs `"DESTROYER TACTICAL P2P COMMAND CENTER"`.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/ui_presentation.md:347` | `tactical` | `- `tactical_web/index.html:29` outputs `"DESTROYER TACTICAL P2P COMMAND CENTER"`.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/modules/ui_presentation.md:348` | `tactical` | `- `tactical_web_console.py:658` prints `"[DEFCON-1 TACTICAL P2P WEB COMMAND CENTER ONLINE]"`.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/open_questions.md:45` | `destroyer` | `1. What is the formal milestone for deprecating and retiring `secure_p2p.py` as an operational entry point in favor o...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/proposals.md:22` | `NC3` | `- 1-byte Message Type: `0x01` (Msg), `0x02` (File), `0x03` (NC3 Directive)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/PUBLICATION_MANIFEST.md:4` | `destroyer` | `**Target Repository:** `Destroyer-official/Destroyer-ST2027`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/PUBLICATION_MANIFEST.md:5` | `destroyer` | `**Target Branch:** `audit/destroyer-st2027-verified-fixes`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_CANDIDATE.md:1` | `destroyer` | `# Release Candidate Specification: Destroyer-ST2027 Verified Fixes` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_CANDIDATE.md:5` | `destroyer` | `**Target Repository:** `https://github.com/Destroyer-official/Destroyer-ST2027`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_CANDIDATE.md:6` | `destroyer` | `**Proposed Remote Branch:** `audit/destroyer-st2027-verified-fixes`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_CANDIDATE.md:38` | `destroyer` | `\| **Gate A** \| Repository Identity & Visibility \| **VERIFIED** \| Remote is `https://github.com/Destroyer-official...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_CANDIDATE.md:43` | `destroyer` | `\| **Gate F** \| Publication Method \| **VERIFIED** \| Dedicated release branch `audit/destroyer-st2027-verified-fixe...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_VERIFICATION.md:5` | `destroyer` | `**Target Repository:** `https://github.com/Destroyer-official/Destroyer-ST2027.git`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_VERIFICATION.md:6` | `destroyer` | `**Target Branch:** `audit/destroyer-st2027-verified-fixes`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_VERIFICATION.md:17` | `destroyer` | `\| **Gate A — Identity & Visibility** \| Remote identity confirmed as `Destroyer-official/Destroyer-ST2027`. Base rem...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_VERIFICATION.md:22` | `destroyer` | `\| **Gate F — Publication Method** \| Dedicated branch `audit/destroyer-st2027-verified-fixes` created from `main`. E...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_VERIFICATION.md:23` | `destroyer` | `\| **Gate G — Post-Push Verification** \| Remote branch ref, remote commit hash, and remote diff verified on GitHub r...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_VERIFICATION.md:29` | `destroyer` | `- **Local Remediation Branch:** `audit/destroyer-st2027-verified-fixes`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_VERIFICATION.md:31` | `destroyer` | `- **Remote Push Target:** `origin/audit/destroyer-st2027-verified-fixes`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_VERIFICATION.md:56` | `destroyer` | `- **GitHub Pull Request:** [`#1: fix(audit): verified engineering remediations, dependency pins, claim updates, and s...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_VERIFICATION.md:58` | `destroyer` | `- **Head Branch:** `audit/destroyer-st2027-verified-fixes`` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/release/RELEASE_VERIFICATION.md:60` | `destroyer` | `- **Merged Main Commit:** `db73f07` (`Merge pull request #1 from Destroyer-official/audit/destroyer-st2027-verified-f...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/audit/remediation_plan.md:86` | `destroyer` | `Mark `secure_p2p.py` as legacy prototype. Verify all test suites point to `core/orchestrator.py` and `destroyer.py`.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/remediation_plan.md:88` | `destroyer` | `Add runtime warning when `secure_p2p.py` is invoked directly via CLI, redirecting operators to `destroyer.py`.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/remediation_plan.md:107` | `tactical` | `4. **Decentralized Tactical Discovery (Category 6):**` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/remediation_plan.md:108` | `tactical` | `- Production configuration (`config_production.json`) binds to `"::"` in air-gapped mode with zero hardcoded bootstra...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/test-results/TEST_AND_BUILD_REPORT.md:6` | `destroyer` | `**Repository:** Destroyer-ST2027 (`D:\code\Main_projects\p2p\p2p_6_1-26`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/test-results/TEST_AND_BUILD_REPORT.md:43` | `tactical` | `4. `test_04_tactical_msg_metadata_tampering_rejected`: Tampered tactical message headers dropped fail-closed.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/test-results/TEST_AND_BUILD_REPORT.md:148` | `tactical` | `- `test_resilient_ddil.py`: Tactical Delay/Disruption Tolerant Networking, out-of-order store-and-forward bundle deli...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/audit/verification_evidence_audit.md:73` | `tactical` | `\| **Tactical Mesh & Diode** \| `test_cjadc2_report_anchor.py`, `test_data_diode_simplex.py`, `test_emergency_zeroiza...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/formal/README.md:3` | `sovereign` | `This directory contains the machine-checked symbolic formal verification models and proofs for the Destroyer-ST2027 s...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/formal/README.md:3` | `destroyer` | `This directory contains the machine-checked symbolic formal verification models and proofs for the Destroyer-ST2027 s...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/formal/handshake_model.pv:81` | `classified` | `(* --- Top-Secret Classified Payload --- *)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/formal/handshake_model.pv:125` | `sovereign` | `(* Sign identity & ephemeral key using Sovereign ML-DSA-87 key *)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/formal/nc3_dual_custody.pv:1` | `NC3` | `(* nc3_dual_custody.pv -- ProVerif Formal Model of NC3 / PAL Two-Person Integrity` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/formal/nc3_dual_custody.pv:6` | `NC3` | `* - CJCSI 3265.01 (NC3 Command & Control Message Security)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `docs/formal/nc3_dual_custody.pv:10` | `nuclear` | `* 1. Nuclear PAL Confidentiality: An adversary with complete network interception` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/formal/nc3_dual_custody.pv:11` | `classified` | `*    AND compromise of Officer 1 CANNOT decrypt or learn the classified PAL code.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/formal/nc3_dual_custody.pv:69` | `classified` | `(* --- High-Value Classified Nuclear PAL Launch Code --- *)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/formal/nc3_dual_custody.pv:69` | `nuclear` | `(* --- High-Value Classified Nuclear PAL Launch Code --- *)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/formal/nc3_dual_custody.pv:126` | `classified` | `(* 3. Symmetric AEAD Encryption of Classified PAL Payload *)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/liboqs_pin.md:27` | `destroyer` | `(`~/.destroyer-st2027/offline-keys/military_root_ca.pem`, encrypted at` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/liboqs_pin.md:117` | `quantum-safe` | `<https://github.com/open-quantum-safe/liboqs>; record commit SHA +` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/liboqs_pin.md:237` | `destroyer` | `--cert-identity 'https://github.com/Destroyer-official/Destroyer-ST2027/.github/workflows/defense_ci.yml@refs/heads/m...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/modules/ca_services.md:21` | `tactical` | `whitelist; `check_hostname=False` is IP-tactical scoping (documented),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/modules/critical_release.md:4` | `nuclear` | `(nuclear-release discipline, technical enforcement layer).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/modules/rust_data_plane.md:38` | `zero-trust` | `- Commands: `keygen`, `auth-keygen`, `auth-sign`, `auth-verify`, `send`, `recv`, `send-file`, `recv-file`, `channel`,...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/modules/rust_data_plane.md:38` | `tactical` | `- Commands: `keygen`, `auth-keygen`, `auth-sign`, `auth-verify`, `send`, `recv`, `send-file`, `recv-file`, `channel`,...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/modules/transport_anonymity.md:5` | `sovereign` | `This module implements **Pillar 4: Network Anonymity & Traffic Shaping** for the 2027 Top-Secret transmission pipelin...` | (b) Standard Identifier | KEEP |
| `docs/modules/transport_anonymity.md:13` | `sovereign` | `\| [`transport_anonymity.py`](transport_anonymity.py) \| ~800 \| SOCKS5 Tor client with remote DNS, sovereign APN pin...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/modules/transport_anonymity.md:25` | `sovereign` | `### 2.2. Sovereign Private APN Pinning (`InterfacePinnedTransport`)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/modules/transport_anonymity.md:26` | `tactical` | `- **Use Case:** Tactical tactical cellular, SATCOM, or direct point-to-point links where Tor is prohibited or unavail...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/modules/ts_hw_layer.md:37` | `classified` | `- Enforces that plain RED traffic (internal classified data) and encrypted BLACK traffic (external transport) travers...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/security_audit_report.md:10` | `sovereign` | `\| **Encryption library** \| `cryptography==50.0.1` (patched against CVE-2024-12797 / GHSA-79v4-65xg-pq4g with exact ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/security_audit_report.md:73` | `sovereign` | `- Residual (needs manual review): sovereign JSON PKI + pinning/DANE/OCSP enforcement not fully traced; `seen_nonces` ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/security_audit_report.md:295` | `SCIF` | `**Scope:** The 4 actionable Layer-1 items from the 5-layer review. Layers 2-5 (seL4/swap/DMA, zeroization mesh, red/b...` | (b) Standard Identifier | KEEP |
| `docs/security_audit_report.md:352` | `tactical` | `- **Tactical-link note:** full McEliece bundles cannot traverse 9.6-64` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/security_audit_report.md:385` | `destroyer` | `11; readiness 8; wave8 16; destroyer 6; tail segment 95; `verify_deployment.py` READY` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/security_audit_report.md:387` | `SCIF` | `- **Residuals (unchanged, non-codeable):** SCIF/TEMPEST/provisioned TPM/facility work and` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/security_audit_report.md:394` | `sovereign` | `**Scope:** Formal verification and closeout of the 5 Strategic Pillars required for Top-Secret / 2027 sovereign commu...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/security_audit_report.md:421` | `sovereign` | `- **Overlay Anonymity (`transport_anonymity.py:1-420`):** Direct public IP connections refused in TS mode. Enforces T...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `docs/security_audit_report.md:424` | `top secret` | `- **Transmit Authorization / DPO (`spo_dpo.py:1-508`):** DoD S-5210.41M Two-Person Integrity (TPI) enforcement: Dual-...` | (b) Standard Identifier | KEEP |
| `double_ratchet.py:35` | `NC3` | `3. Message Origin Authentication & Non-Repudiation: High-assurance per-message post-quantum digital signatures (FALCO...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `double_ratchet.py:1450` | `maximum security` | `- For maximum security, use bytearray for sensitive data storage` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `double_ratchet.py:2128` | `top secret` | `# TOP SECRET or non-repudiation is strictly required (P2P_TS_MODE=1 or` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `double_ratchet.py:2129` | `top secret` | `# P2P_REQUIRE_NON_REPUDIATION=1); never usable for TOP SECRET / DPO payloads.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `double_ratchet.py:2142` | `top secret` | `"(AEAD-only repudiable auth; NOT for TOP SECRET/DPO use)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `double_ratchet.py:2237` | `maximum security` | `# Enhanced security options - force to maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `double_ratchet.py:3594` | `maximum security` | `# or combine both for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `double_ratchet.py:5007` | `maximum security` | `SecurityError: Always raises this error to maintain maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `double_ratchet.py:5042` | `maximum security` | `This method always returns the MAXIMUM security level settings,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `double_ratchet.py:5051` | `maximum security` | `# Always use MAXIMUM security level regardless of input parameter` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `group_key_manager.py:119` | `top secret` | `"TOP SECRET": 3,` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `hybrid_kex_legacy.py:450` | `maximum security` | `# Use HKDF-sha3_512 for maximum security (NIST Level-5)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `hybrid_kex_legacy.py:656` | `maximum security` | `# No fallback - hardware backing is required for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `hybrid_kex_legacy.py:3455` | `maximum security` | `This function is designed for maximum security with FALCON-1024 signatures` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `hybrid_kex_legacy.py:3476` | `maximum security` | `No fallbacks or downgrades are permitted for maximum security.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `key_fill_import.py:20` | `classified` | `remains the accredited path for classified use).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `launch_tactical_terminals.bat:4` | `tactical` | `echo   SPAWNING 2 TACTICAL MILITARY P2P TERMINALS (ST2027 DEFCON-1)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `launch_tactical_web.bat:3` | `tactical` | `title DEFCON-1 TACTICAL P2P WEB COMMAND CENTER` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `launch_tactical_web.bat:5` | `destroyer` | `echo   LAUNCHING DESTROYER DEFCON-1 TACTICAL P2P WEB COMMAND CENTER` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `launch_tactical_web.bat:5` | `tactical` | `echo   LAUNCHING DESTROYER DEFCON-1 TACTICAL P2P WEB COMMAND CENTER` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `liboqs_wrapper.py:7` | `maximum security` | `Hybrid Strategy for Maximum Security:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `liboqs_wrapper.py:245` | `quantum-safe` | `subprocess.run(["git", "clone", "--depth", "1", "--branch", "0.16.0", "https://github.com/open-quantum-safe/liboqs.gi...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `liboqs_wrapper.py:1024` | `maximum security` | `This implementation provides maximum security and flexibility:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `liboqs_wrapper.py:1361` | `maximum security` | `print("  * Maximum security: Attacker must break multiple algorithm families")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `logging_config.py:82` | `maximum security` | `"MAXIMUM SECURITY ACHIEVED",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:3` | `maximum security` | `Maximum Security Hardening Module` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:55` | `maximum security` | `"""Exception raised when maximum security requirements cannot be met."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:56` | `maximum security` | `def __init__(self, message: str = "Maximum security requirements failed", details: Optional[Dict[str, Any]] = None):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:83` | `maximum security` | `Maximum Security Hardening implementation with no fallbacks.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:90` | `maximum security` | `"""Initialize maximum security hardening."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:123` | `maximum security` | `description="Administrator/root privileges required for maximum security",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:234` | `maximum security` | `max_security_logger.warning("SECURITY NOTICE: Administrator privileges recommended for maximum security")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:426` | `maximum security` | `# Configure for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:561` | `maximum security` | `Enforce maximum security requirements with no fallbacks.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:566` | `maximum security` | `max_security_logger.info("Enforcing maximum security requirements...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:604` | `maximum security` | `max_security_logger.critical("MAXIMUM SECURITY ENFORCEMENT FAILED")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:613` | `maximum security` | `max_security_logger.info("[PASS] ALL MAXIMUM SECURITY REQUIREMENTS SATISFIED")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:632` | `maximum security` | `Enforce maximum security or fail the application.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:641` | `maximum security` | `max_security_logger.info("MAXIMUM SECURITY ACHIEVED - SYSTEM READY")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:644` | `maximum security` | `max_security_logger.critical("MAXIMUM SECURITY REQUIREMENTS NOT MET")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:655` | `maximum security` | `"""Main function for testing maximum security hardening."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:657` | `maximum security` | `max_security_logger.info("Starting Maximum Security Hardening test")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:665` | `maximum security` | `max_security_logger.info("Maximum Security Hardening test completed successfully")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `maximum_security_hardening.py:672` | `maximum security` | `max_security_logger.error(f"Maximum Security Hardening test failed: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `memory_manager.py:12` | `classified` | `• §4-2: Memory Protection Requirements for Classified Information Systems` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `memory_manager.py:191` | `maximum security` | `and memory protection extensions for maximum security isolation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `memory_manager.py:1513` | `maximum security` | `# Enable maximum security hardening` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `memory_manager.py:1534` | `maximum security` | `"""Enable maximum security hardening."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `memory_manager.py:1546` | `maximum security` | `memory_logger.info("Maximum security hardening enabled")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `memory_manager.py:1633` | `maximum security` | `# Verify maximum security level` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:135` | `nuclear` | `elif cmd in ('/eam', '/nuclear'):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:211` | `tactical` | `print(f"  {BOLD}/silence{RESET} - Toggle tactical network cloak and background chaff")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:217` | `NC3` | `print(f"  {BOLD}/eam <directive>{RESET} - Seal and transmit NC3 Emergency Action Message (Two-Person Rule)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:218` | `sovereign` | `print(f"  {BOLD}/zgdp{RESET} - Sovereign Zero-Gap Defense Pipeline telemetry (multi-language dual-lock)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:220` | `tactical` | `print(f"  {BOLD}/cot <lat> <lon> <call>{RESET} - Emit Cursor-on-Target tactical military event")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:323` | `sovereign` | `print(f"  Auth Mechanism: {GREEN}Sovereign Mutual ML-DSA-87 Certificate Pinning (OAuth disabled){RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:494` | `tactical` | `"""Toggle tactical cloaking and background traffic chaffing."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:502` | `tactical` | `print(f"\n{BOLD}{YELLOW}[TACTICAL ROUTING] Tactical Cloak: DISENGAGED{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:506` | `tactical` | `print(f"\n{BOLD}{GREEN}[TACTICAL ROUTING] Tactical Cloak: ENGAGED{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:510` | `tactical` | `print(f"\n{RED}Error toggling tactical cloak: {e}{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:560` | `tactical` | `print(f"  Tactical Cloak Enforced:  {GREEN if tactical_cloak_enabled() else YELLOW}{tactical_cloak_enabled()}{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:627` | `tactical` | `print(f"  {BOLD}TRAFFIC FLOW CONFIDENTIALITY & TACTICAL CLOAKING{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:640` | `nuclear` | `"""Handle /eam and /nuclear Emergency Action Message command under Two-Person Integrity."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:679` | `classified` | `# Fail closed: a classified NC3 directive must never be sent` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:679` | `NC3` | `# Fail closed: a classified NC3 directive must never be sent` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:682` | `NC3` | `"NC3 EAM directive requires an authenticated encrypted "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:686` | `NC3` | `print(f"\n{BOLD}{GREEN}[NC3 DIRECTIVE RELEASED]{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:693` | `NC3` | `print(f"\n{RED}Error releasing NC3 EAM directive: {e}{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:712` | `sovereign` | `print(f"  {BOLD}SOVEREIGN ZERO-GAP DEFENSE PIPELINE (ZGDP) TELEMETRY{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:720` | `NC3` | `print(f"  Dual Custody / NC3:       ACTIVE (120s temporal validity, ML-DSA-87)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `messaging/commands.py:749` | `tactical` | `"""Handle /cot command to emit a Cursor-on-Target tactical event."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `nc3_nuclear_command.py:10` | `NC3` | `authorization windows). All directives, keys, and classification banners (e.g., SI-OP-IA, NC3)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:12` | `nuclear command` | `Operational Nuclear Command, Control, and Communications (NC3) requires dedicated` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `nc3_nuclear_command.py:12` | `nuclear` | `Operational Nuclear Command, Control, and Communications (NC3) requires dedicated` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:12` | `NC3` | `Operational Nuclear Command, Control, and Communications (NC3) requires dedicated` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:42` | `NC3` | `EAM_PREAMBLE = "[NC3/EAM-AUTH-DEFCON-1]"` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:43` | `top secret` | `EAM_CLASSIFICATION = "TOP SECRET // SI-OP-IA // NC3 // NOFORN"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `nc3_nuclear_command.py:43` | `NC3` | `EAM_CLASSIFICATION = "TOP SECRET // SI-OP-IA // NC3 // NOFORN"` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:49` | `nuclear command` | `"""Base exception for all Nuclear Command and Control protocol violations."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `nc3_nuclear_command.py:49` | `nuclear` | `"""Base exception for all Nuclear Command and Control protocol violations."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:135` | `top secret` | `# or TOP SECRET mode is a fail-closed integrity event, not a cue to` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `nc3_nuclear_command.py:175` | `NC3` | `"MILITARY FATAL: Serialization of NC3 secret signing keys to dictionaries/JSON "` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:180` | `NC3` | `"[NC3-SEC-WARN] Secret key exported in officer profile dictionary (testing only)."` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:321` | `NC3` | `hasher.update(b"NC3-VSS-SHARE-COMMITMENT-V1:")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:330` | `NC3` | `hasher.update(b"NC3-VSS-SECRET-COMMITMENT-V1:")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:433` | `NC3` | `"""Challenge issued by NC3 system to physically present hardware security tokens."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:533` | `sovereign` | `"""Generate sovereign ML-DSA-87 keypair for an authorized strategic officer."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `nc3_nuclear_command.py:590` | `NC3` | `hasher.update(b"NC3-HW-AUTH-CHALLENGE-V1:")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:846` | `NC3` | `f"NC3 DUAL-CUSTODY TEMPORAL BREACH: Officers authorized {sync_delta:.3f}s apart "` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:949` | `NC3` | `info=b"NC3/PAL-DUAL-CUSTODY-V1"` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:969` | `nuclear` | `Creates, dual-encrypts, and dual-signs a nuclear-grade Emergency Action Message.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:1094` | `nuclear` | `message=f"NUCLEAR EAM CREATED: {eam_id} [Directive: {directive_code}] Dual-Custody Verified.",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:1124` | `zero-trust` | `# Strict Zero-Trust Peer Verification Gate` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `nc3_nuclear_command.py:1132` | `zero-trust` | `f"under military zero-trust policy. Out-of-band safety number confirmation required."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `nc3_nuclear_command.py:1284` | `nuclear` | `message=f"NUCLEAR EAM VERIFIED & OPENED: {eam_id} [Directive: {eam_data['directive_code']}].",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:1441` | `NC3` | `# Global NC3 Controller Singleton` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:1454` | `sovereign` | `or generates and provisions sovereign credentials if not present.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `nc3_nuclear_command.py:1524` | `NC3` | `nonce, raw, f"NC3-OFFICER-CREDS-V2:{officer_id}".encode("utf-8")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:1562` | `NC3` | `nonce, ct, f"NC3-OFFICER-CREDS-V2:{officer_id}".encode("utf-8")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:1605` | `sovereign` | `# Generate fresh sovereign officer credentials (first provisioning only).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `nc3_nuclear_command.py:1699` | `NC3` | `Ensures baseline Strategic Command & Pentagon officer credentials exist for NC3 dual-custody operation.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:1722` | `NC3` | `Serializes an NC3 EAM dictionary with mandatory 1024-byte uniform block padding` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:1749` | `NC3` | `ct = AESGCM(aead_key).encrypt(nonce, padded_payload, b"NC3-EAM-WIRE-V1")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:1756` | `NC3` | `Deserializes an NC3 EAM wire frame, decrypting AEAD envelope if keyed and` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `nc3_nuclear_command.py:1771` | `NC3` | `padded_payload = AESGCM(aead_key).decrypt(nonce, ct, b"NC3-EAM-WIRE-V1")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `network/session_manager.py:363` | `tactical` | `# Check Tactical Network Cloaking Policy (SIGINT / Geolocation Protection)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `network/session_manager.py:372` | `tactical` | `if "TACTICAL CLOAK VIOLATION" in str(e_cloak):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `network_endpoint_discovery.py:13` | `tactical` | `- Air-gap / Tactical Cloak Safe: When P2P_TACTICAL_CLOAK or P2P_AIR_GAPPED is active,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `network_endpoint_discovery.py:427` | `tactical` | `status_msg = "Air-Gap/Tactical Cloak Active (STUN Suppressed)" if posture.air_gap_mode else "STUN not queried or NAT ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `noise_pq.py:99` | `destroyer` | `WireGuard cookie). In Destroyer ST2027, the handshake runs over connection-` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `openssl_cnsa2_posture.cnf:2` | `zero-trust` | `# Destroyer-ST2027 CNSA 2.0 / DoD Zero-Trust OpenSSL Configuration Template` | (b) Standard Identifier | KEEP |
| `openssl_cnsa2_posture.cnf:2` | `destroyer` | `# Destroyer-ST2027 CNSA 2.0 / DoD Zero-Trust OpenSSL Configuration Template` | (b) Standard Identifier | KEEP |
| `p2p_core.py:412` | `tactical` | `self.logger.info("STUN discovery inactive or disabled (Tactical Stealth / Dark P2P Mode)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `p2p_core.py:1144` | `NC3` | `Mitigates pre-auth DoS attacks on handshakes and ensures NC3/EAM release window availability.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `platform_hsm_interface.py:597` | `maximum security` | `and memory protection extensions for maximum security isolation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `platform_hsm_interface.py:2347` | `maximum security` | `enhanced_security (bool, optional): Enable maximum security features including memory protection, integrity verificat...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `platform_hsm_interface.py:9010` | `tactical` | `# IP-tactical-only: Server-side context does not check client hostname, but enforces mTLS CERT_REQUIRED` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `pqc_algorithms.py:308` | `maximum security` | `# These are the PRIMARY implementations - always use hybrid for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `pqc_algorithms.py:312` | `maximum security` | `pqc_logger.info("[OK] Primary algorithms set to HYBRID for maximum security")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `pqc_algorithms.py:2237` | `maximum security` | `# Use HKDF-SHA3_512 for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `pqc_algorithms.py:3776` | `tactical` | `for interactive tactical communication, or optional McEliece-8192128f hybrid` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `production_gate.py:150` | `sovereign` | `"""True when sovereign/TS posture is requested OR production is sticky."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `red_team_adversarial_drill.py:4` | `sovereign` | `Automated Red-Team Adversarial Penetration Drill for Sovereign Military Defense Communications.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `red_team_adversarial_drill.py:272` | `top secret` | `legit_frame = node_tx.transmit(b"TOP SECRET TARGET COORDINATES")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `red_team_adversarial_drill.py:280` | `top secret` | `assert res1 is not None and res1[0] == b"TOP SECRET TARGET COORDINATES"  # nosec: B101` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `requirements.txt:1` | `military-grade` | `# Military-Grade Secure P2P Requirements (NIST L5 / CNSA 2.0, 2028 hardening)` | (b) Standard Identifier | KEEP |
| `resilient_communication.py:6` | `tactical` | `Buffers outbound traffic across intermittent tactical connectivity, enforces` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `resilient_communication.py:14` | `tactical` | `- RFC 896 / Tactical link backoff pacing bounds (1s to 60s ceiling)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/Cargo.toml:5` | `sovereign` | `description = "Rust data plane for sovereign direct-IPv6 P2P: AEAD framing, anti-replay, padding, chaff, silent-drop"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/Cargo.toml:39` | `NC3` | `# Simulated NC3/EAM/PTT/CoT lab surfaces. Production builds MUST disable` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/Cargo.toml:42` | `NC3` | `# runtime. Defensive NC3 safety-gate checks remain available unconditionally.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/pyproject.toml:6` | `destroyer` | `name = "destroyer-core"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/pyproject.toml:8` | `sovereign` | `description = "Rust data plane for sovereign direct-IPv6 P2P (isolated crate, tested before integration)"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/acd.rs:59` | `tactical` | `// Tactical cloaking active flag` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/acd.rs:124` | `tactical` | `/// Check if tactical cloaking / chaff increase is active.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/aead.rs:49` | `destroyer` | `hk.expand(b"destroyer/header-protection/v2", &mut hp_key)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/aead.rs:55` | `destroyer` | `/// `info` MUST be domain-separated per use (e.g. b"destroyer/frame/v1").` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/aead.rs:337` | `destroyer` | `let a = FrameKey::derive(&secret, b"destroyer/frame/v1");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/aead.rs:338` | `destroyer` | `let b = FrameKey::derive(&secret, b"destroyer/frame/v1");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/aead.rs:339` | `destroyer` | `let c = FrameKey::derive(&secret, b"destroyer/frame/v2");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/cot.rs:3` | `tactical` | `//! Provides post-quantum authenticated tactical situational awareness formatting,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/cot.rs:10` | `tactical` | `/// Standard Cursor-on-Target tactical event representation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/doc_transfer.rs:3` | `tactical` | `//! Encapsulates files into in-band tactical document streams that travel securely across` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/doc_transfer.rs:159` | `top secret` | `let content = b"TOP SECRET // OPERATION OMEGA TACTICAL FLIGHT PLAN // DEFCON-1";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/doc_transfer.rs:159` | `tactical` | `let content = b"TOP SECRET // OPERATION OMEGA TACTICAL FLIGHT PLAN // DEFCON-1";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/fec.rs:367` | `sovereign` | `let d0 = b"Hello Sovereign!".to_vec();` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/ffi.rs:1129` | `NC3` | `use crate::nc3::{check_nc3_safety_gate, create_eam, verify_eam, verify_two_person_rule, EamDirective};` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/fragment.rs:364` | `tactical` | `let p_small = b"hello tactical world";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/fragment.rs:385` | `classified` | `data: b"classified tactical coordinates".to_vec(),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/fragment.rs:385` | `tactical` | `data: b"classified tactical coordinates".to_vec(),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/group_ratchet.rs:1` | `sovereign` | `//! Sovereign Sender-Key Group Ratchet Engine, wire profile v2.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/group_ratchet.rs:5` | `NC3` | `//! canonical length-prefixed context-bound AAD, and DoD/NC3 Two-Person` | (b) Standard Identifier | KEEP |
| `rust_data_plane/src/group_ratchet.rs:41` | `sovereign` | `pub const GROUP_PROTO_ID: &[u8] = b"ST2027-SOVEREIGN-GROUP-v2";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/group_ratchet.rs:247` | `sovereign` | `/// Sovereign Group Ratchet Session.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/group_ratchet.rs:578` | `top secret` | `let msg = b"TOP SECRET: REGROUP AT COORDINATES X-RAY";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/group_ratchet.rs:683` | `NC3` | `SovereignGroupRatchet::new("STRATCOM-NC3".into(), "NORAD".into(), epoch_secret)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/kem.rs:193` | `destroyer` | `info.extend_from_slice(b"DESTROYER-ST2027-TRANSCRIPT-BOUND-KEY-AES256GCM-v2");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/kem.rs:315` | `sovereign` | `let k_psk = derive_session_key_transcript(&ss, Some(b"sovereign-psk"), &transcript);` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/keystore.rs:15` | `top secret` | `//!   prefer stdin + `LockedKey32` / HSM custody for TOP SECRET; files are` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/keystore.rs:160` | `top secret` | `// for TOP SECRET.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/lib.rs:62` | `NC3` | `pub mod nc3;` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/lib.rs:290` | `zero-trust` | `/// Bind a peer identifier and enable continuous active cyber defense & zero-trust tracking.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:109` | `zero-trust` | `zero-trust-eval --peer ID [--role ROLE] [--penalty N] [--reward N]           evaluate NIST SP 800-207 continuous trus...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:111` | `classified` | `tactical-msg [--precedence (Y\|Z\|O\|P\|R)] [--clearance LEVEL] [--caveats CAVEAT] --msg TEXT  format classified mili...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:111` | `tactical` | `tactical-msg [--precedence (Y\|Z\|O\|P\|R)] [--clearance LEVEL] [--caveats CAVEAT] --msg TEXT  format classified mili...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:112` | `NC3` | `eam-auth --directive TEXT --officer1-pk PATH --officer1-sig PATH --officer2-pk PATH --officer2-sig PATH [--officers-m...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:352` | `destroyer` | `hk.expand(b"DESTROYER-ST2027-STATE-FILE-AUTH-SUBKEY-v2", &mut subkey)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:360` | `destroyer` | `mac.update(b"DESTROYER-ST2027-STATE-FILE-AUTH-v2");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:371` | `destroyer` | `mac.update(b"DESTROYER-ST2027-STATE-FILE-AUTH-v2");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:668` | `destroyer` | `get_flag(args, "--domain").unwrap_or_else(\|\| "DESTROYER-ST2027-SIG-GENERIC".to_string());` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:694` | `destroyer` | `get_flag(args, "--domain").unwrap_or_else(\|\| "DESTROYER-ST2027-SIG-GENERIC".to_string());` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:762` | `top secret` | `// use `channel` mode for TOP SECRET.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:1123` | `zero-trust` | `// Zero-Trust continuous risk engine self-check` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:1144` | `zero-trust` | `eprintln!("selftest: cookie-gate ok, acd-defense ok, zero-trust ok, memory-guard ok");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2566` | `zero-trust` | `"zero-trust-eval SUCCESS: peer={peer} role={role_name} score={score}/100 trusted={trusted} perm_allowed={:?}",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2579` | `tactical` | `local inputs; this is a demo/lab formatter, not an operational tactical data link publish."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2581` | `tactical` | `let callsign = get_flag(args, "--callsign").unwrap_or_else(\|\| "TACTICAL-ST2027".to_string());` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2617` | `destroyer` | `let sig = sk.sign(b"DESTROYER-ST2027-COT-EVENT", cot_xml.as_bytes());` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2638` | `tactical` | `// F-15 fence: tactical-msg is a FORMATTER that renders an MMHS-style` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2642` | `tactical` | `"FORMATTER NOTICE (stderr): tactical-msg formats an MMHS precedence telegram; \` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2655` | `classified` | `// F-15: RTB classified-spillage scan is ON BY DEFAULT. --scan-rtb is` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2680` | `classified` | `fail(&format!("RTB SPILLAGE PREVENTED: detected classified indicator '{indicator}' in {clearance_str} message"));` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2687` | `tactical` | `"tactical-msg SUCCESS: clearance={clearance_str} precedence={prec_label} caveats={caveats}"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2730` | `NC3` | `fail("NC3 TWO-PERSON RULE VIOLATION: Officer 1 and Officer 2 keys are identical (single-custody attempt)");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2745` | `NC3` | `let domain = b"DESTROYER-ST2027-NC3-EAM";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2745` | `destroyer` | `let domain = b"DESTROYER-ST2027-NC3-EAM";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2759` | `NC3` | `println!("eam-auth SUCCESS: NC3 TWO-PERSON RULE DUAL CUSTODY VERIFIED (DoD S-5210.41M)");` | (b) Standard Identifier | KEEP |
| `rust_data_plane/src/main.rs:2767` | `NC3` | `match destroyer_core::nc3::check_nc3_safety_gate(msg.as_bytes()) {` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2769` | `nuclear command` | `println!("nc3-safety-gate: PASS (no nuclear command keywords detected)");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2769` | `nuclear` | `println!("nc3-safety-gate: PASS (no nuclear command keywords detected)");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2769` | `NC3` | `println!("nc3-safety-gate: PASS (no nuclear command keywords detected)");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2772` | `nuclear` | `fail(&format!("NC3 SAFETY GATE VIOLATION: detected single-officer nuclear directive indicator '{indicator}'"));` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2772` | `NC3` | `fail(&format!("NC3 SAFETY GATE VIOLATION: detected single-officer nuclear directive indicator '{indicator}'"));` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2832` | `zero-trust` | `"zero-trust-eval" => cmd_zero_trust_eval(&args[2..]),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2839` | `tactical` | `"tactical-msg" => {` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2843` | `tactical` | `{ fail("tactical-msg is a simulated/lab surface and is not available in production builds"); }` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/main.rs:2851` | `NC3` | `"nc3-safety-gate" => cmd_nc3_safety_gate(&args[2..]),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/mmhs.rs:4` | `destroyer` | `//! envelopes used by the destroyer data-plane.  Every outbound telegram` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/mmhs.rs:7` | `classified` | `//! classified indicators are fail-closed rejected.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/mmhs.rs:191` | `classified` | `/// (`inspect_content_rtb`).  If the scan detects a classified indicator` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/mmhs.rs:311` | `top secret` | `// "top secret" is a dirty word; SECRET clearance must be rejected.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/mmhs.rs:312` | `top secret` | `let msg = b"Relay top secret coordinates to HQ";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/mmhs.rs:325` | `top secret` | `let msg = b"Relay top secret coordinates to HQ";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:1` | `nuclear command` | `//! NC3 (Nuclear Command, Control, and Communications) Operations.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:1` | `nuclear` | `//! NC3 (Nuclear Command, Control, and Communications) Operations.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:1` | `NC3` | `//! NC3 (Nuclear Command, Control, and Communications) Operations.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `rust_data_plane/src/nc3.rs:5` | `NC3` | `//! Messages (EAM). Also provides the NC3 Safety Gate scanner that blocks` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `rust_data_plane/src/nc3.rs:6` | `nuclear` | `//! single-officer nuclear directives from leaking through routine conversational chat.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:12` | `NC3` | `/// Cryptographic domain separation string for NC3 Emergency Action Messages.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `rust_data_plane/src/nc3.rs:13` | `NC3` | `pub const NC3_EAM_DOMAIN: &[u8] = b"DESTROYER-ST2027-NC3-EAM";` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `rust_data_plane/src/nc3.rs:13` | `destroyer` | `pub const NC3_EAM_DOMAIN: &[u8] = b"DESTROYER-ST2027-NC3-EAM";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:18` | `classified` | `/// NC3 Safety Gate classified & nuclear directive trigger keywords.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:18` | `nuclear` | `/// NC3 Safety Gate classified & nuclear directive trigger keywords.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:18` | `NC3` | `/// NC3 Safety Gate classified & nuclear directive trigger keywords.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `rust_data_plane/src/nc3.rs:20` | `NC3` | `/// unless routed through the authenticated dual-custody NC3 pipeline.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `rust_data_plane/src/nc3.rs:23` | `nuclear` | `b"nuclear strike",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:26` | `nuclear` | `b"nuclear release",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:31` | `nuclear` | `b"nuclear warhead",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:39` | `nuclear` | `/// Scan a message for unauthorized NC3 nuclear directive keywords in routine traffic.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:39` | `NC3` | `/// Scan a message for unauthorized NC3 nuclear directive keywords in routine traffic.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `rust_data_plane/src/nc3.rs:57` | `nuclear` | `b"nuclear strike" => "nuclear strike",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:60` | `nuclear` | `b"nuclear release" => "nuclear release",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:65` | `nuclear` | `b"nuclear warhead" => "nuclear warhead",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:156` | `NC3` | `/// Create an authentic dual-officer signed NC3 Emergency Action Message.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `rust_data_plane/src/nc3.rs:183` | `NC3` | `/// Verify an NC3 EAM directive against two enrolled officer keys.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `rust_data_plane/src/nc3.rs:223` | `tactical` | `assert!(check_nc3_safety_gate(b"routine tactical update coordinates 38N").is_ok());` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:245` | `nuclear` | `check_nc3_safety_gate(b"AUTHORIZE NUCLEAR RELEASE NOW"),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nc3.rs:246` | `nuclear` | `Err("nuclear release")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/nostd_microcore.rs:336` | `NC3` | `let payload = b"TOP-SECRET-NC3-WAR-DIRECTIVE-ZULU-99";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:4` | `NC3` | `//!   - Pre-flight: NSA RTB dirty-word spillage scan + NC3 safety gate detection` | (b) Standard Identifier | KEEP |
| `rust_data_plane/src/pipeline.rs:15` | `NC3` | `use crate::nc3::check_nc3_safety_gate;` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:29` | `destroyer` | `pub const LAYER2_HKDF_SALT: &[u8] = b"destroyer-p2p-rust-v1";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:30` | `destroyer` | `pub const LAYER2_HKDF_INFO: &[u8] = b"destroyer/frame/v1";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:31` | `destroyer` | `pub const CER_HKDF_SALT: &[u8] = b"destroyer-cer-epoch-v1";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:32` | `NC3` | `pub const WAR_KEY_HKDF_SALT: &[u8] = b"destroyer-nc3-war-key-salt";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:32` | `destroyer` | `pub const WAR_KEY_HKDF_SALT: &[u8] = b"destroyer-nc3-war-key-salt";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:45` | `NC3` | `/// Derive a 32-byte military NC3 DEFCON-1 war-key from master keying material.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:216` | `classified` | `// ── Pre-flight 1: RTB classified indicator scan ──────────────────` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:223` | `NC3` | `// ── Pre-flight 2: NC3 safety gate keyword scan ───────────────────` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:225` | `nuclear` | `// Single-officer routine message contains nuclear directives! Block fail-closed.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:354` | `classified` | `let data = b"Classified military tactical datagram payload";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:354` | `tactical` | `let data = b"Classified military tactical datagram payload";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/pipeline.rs:395` | `tactical` | `let msg = b"AUTHENTICATED TACTICAL COORDINATES";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/policy.rs:64` | `zero-trust` | `/// Zero-Trust continuous risk score dropped below threshold or RBAC unauthorized.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/policy.rs:86` | `zero-trust` | `write!(f, "zero-trust continuous verification failure")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/ptt.rs:1` | `tactical` | `//! Push-To-Talk (PTT) Tactical Voice Burst Envelope.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/ptt.rs:4` | `tactical` | `//! for low-latency tactical tactical radio transmission across zero-gap multi-layer channels.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/ptt.rs:86` | `tactical` | `/// Package audio bytes into a tactical voice burst wire envelope:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/tpm_nv.rs:18` | `destroyer` | `//!   the session key (HKDF subkey `DESTROYER-ST2027-NVCK-AUTH-SUBKEY-v1`),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/tpm_nv.rs:505` | `destroyer` | `hk.expand(b"DESTROYER-ST2027-NVCK-AUTH-SUBKEY-v2", &mut okm)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/tpm_nv.rs:513` | `destroyer` | `mac.update(b"DESTROYER-ST2027-NVCK-v2");` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:1` | `zero-trust` | `//! Zero-Trust Continuous Verification & Risk Scoring Engine.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:3` | `zero-trust` | `//! Enforces DoD / NIST SP 800-207 Zero-Trust Architecture:` | (b) Standard Identifier | KEEP |
| `rust_data_plane/src/zero_trust.rs:77` | `classified` | `/// Bell-LaPadula Star-Property (No Write Down): Prevents classified spillage.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:83` | `classified` | `/// NSA NCDSMO 'Raise the Bar' (RTB) Dirty-Word / Classified Indicator Filter.` | (b) Standard Identifier | KEEP |
| `rust_data_plane/src/zero_trust.rs:84` | `classified` | `/// Scans outbound data for unauthorized classified markers in constant-time slice traversal.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:86` | `top secret` | `const DIRTY_WORDS: [&[u8]; 4] = [b"top secret", b"si-tk-g", b"noforn", b"orcon"];` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:100` | `top secret` | `b"top secret" => Err("TOP_SECRET_INDICATOR"),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:366` | `top secret` | `// 1. No Read Up: Secret cannot read Top Secret` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:376` | `top secret` | `// 2. Read at or below clearance: Top Secret can read Secret` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:386` | `top secret` | `// 3. Caveat mismatch: Top Secret without REL_TO_COALITION cannot read object requiring it` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:401` | `top secret` | `// 5. Star-Property (Write Up/Equal allowed): Secret can write to Secret or Top Secret` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:414` | `tactical` | `let clean_payload = b"TACTICAL STATUS: ALL RADAR UNITS FUNCTIONAL AND REPORTING GREEN";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:417` | `top secret` | `let dirty_payload_1 = b"CLASSIFIED TARGET LOCATIONS: TOP SECRET // SI-OP-IA // NOFORN";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `rust_data_plane/src/zero_trust.rs:417` | `classified` | `let dirty_payload_1 = b"CLASSIFIED TARGET LOCATIONS: TOP SECRET // SI-OP-IA // NOFORN";` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/cavp_algorithm_validator.py:42` | `sovereign` | `"module_name": "SecureP2P Sovereign Cryptographic Module",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/deploy_canary_pilot.py:33` | `tactical` | `Orchestrates tactical canary node deployment and collects continuous` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/deploy_canary_pilot.py:61` | `tactical` | `# Probe 2: Tactical Cloaking & Zero Public Socket Egress` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/deploy_canary_pilot.py:130` | `tactical` | `"""Verify tactical cloaking router prohibits raw public IP egress."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/deploy_canary_pilot.py:163` | `tactical` | `"title": "Tactical Cloaking & Zero Public Socket Egress",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/deploy_canary_pilot.py:165` | `tactical` | `"details": "Direct public IP blocked; tactical overlay subnet (10.99.0.0/16) permitted"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_sar.py:6` | `sovereign` | `for the Sovereign Military Communications Platform under DoD Continuous ATO (cATO).` | (b) Standard Identifier | KEEP |
| `scripts/generate_oscal_sar.py:45` | `sovereign` | `"title": "Sovereign Military Defense Platform - Continuous Security Assessment Results (SAR) & POA&M",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_sar.py:190` | `tactical` | `"title": "Tactical Hardware HSM Micro-Firmware Upgrades",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_ssp.py:6` | `sovereign` | `mapped to NIST SP 800-53 Rev 5 and CNSSI 1253 for the Sovereign Military Defense Platform.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_ssp.py:39` | `sovereign` | `"title": "Sovereign Military P2P Communications Platform - System Security Plan (SSP)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_ssp.py:64` | `sovereign` | `"id": "sovereign-defense-hq",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_ssp.py:66` | `sovereign` | `"name": "Sovereign Defense Communications Command",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_ssp.py:76` | `sovereign` | `"system-name": "Sovereign Military P2P Tactical Mesh",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_ssp.py:76` | `tactical` | `"system-name": "Sovereign Military P2P Tactical Mesh",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_ssp.py:77` | `destroyer` | `"system-name-short": "Destroyer-P2P",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_ssp.py:78` | `zero-trust` | `"description": "Quantum-resistant, zero-trust, peer-to-peer tactical communications platform utilizing native FIPS 20...` | (b) Standard Identifier | KEEP |
| `scripts/generate_oscal_ssp.py:78` | `tactical` | `"description": "Quantum-resistant, zero-trust, peer-to-peer tactical communications platform utilizing native FIPS 20...` | (b) Standard Identifier | KEEP |
| `scripts/generate_oscal_ssp.py:84` | `NC3` | `"title": "National Security Communications (NC3 & Defense Mesh)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_ssp.py:85` | `tactical` | `"description": "Tactical voice, text, telemetry, and critical command authentication data.",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_oscal_ssp.py:147` | `zero-trust` | `"description": "Access Enforcement: Strict Zero-Trust RBAC engine enforces least privilege and default-deny.",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:55` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:77` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:100` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:121` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:142` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:199` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:215` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:235` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:241` | `sovereign` | `"name": "Mutual TLS 1.3 with Sovereign ML-DSA-87 Certificates",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:242` | `sovereign` | `"version": "RFC 8446 Strict Sovereign Profile",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:251` | `quantum-safe` | `"quantumSecurity": "quantum-safe",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:305` | `sovereign` | `"name": "Sovereign Military Defense P2P Platform",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_production_cbom.py:307` | `sovereign` | `"description": "NSA CNSA 2.0 & FIPS 140-3 Sovereign Tactical Communications Asset"` | (b) Standard Identifier | KEEP |
| `scripts/generate_production_cbom.py:307` | `tactical` | `"description": "NSA CNSA 2.0 & FIPS 140-3 Sovereign Tactical Communications Asset"` | (b) Standard Identifier | KEEP |
| `scripts/generate_production_cbom.py:313` | `sovereign` | `"name": "Sovereign Defense Architecture Directorate",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:5` | `sovereign` | `Generates the complete 2027+ Sovereign Post-Quantum PKI hierarchy for the` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:9` | `sovereign` | `1. Sovereign Root CA (Self-signed ML-DSA-87 + NIST P-521 anchor)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:10` | `sovereign` | `2. Sovereign Tactical Issuing CA (Sub CA signed by Root CA)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:10` | `tactical` | `2. Sovereign Tactical Issuing CA (Sub CA signed by Root CA)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:11` | `tactical` | `3. Tactical Node Alpha Identity Certificate (Signed by Sub CA)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:12` | `tactical` | `4. Tactical Node Bravo Identity Certificate (Signed by Sub CA)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:41` | `sovereign` | `print(f"[*] Generating Sovereign Post-Quantum PKI in: {certs_dir}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:45` | `sovereign` | `# 1. Generate Sovereign Root CA` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:46` | `sovereign` | `print("  -> Creating Sovereign Root CA (ML-DSA-87 + P-521)...")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:47` | `sovereign` | `root_ca = PQCertificateAuthority(ca_name="Sovereign-Defense-Root-CA")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:76` | `sovereign` | `# 2. Generate Sovereign Subordinate / Tactical Issuing CA` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:76` | `tactical` | `# 2. Generate Sovereign Subordinate / Tactical Issuing CA` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:77` | `sovereign` | `print("  -> Creating Sovereign Subordinate Issuing CA...")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:80` | `sovereign` | `subject="CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:80` | `tactical` | `subject="CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:104` | `tactical` | `print("  -> Issuing Tactical Node Alpha Certificate...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:108` | `tactical` | `"subject": "CN=tactical-node-alpha.mil,OU=Forward Base Alpha,O=Tactical P2P,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:109` | `sovereign` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:109` | `tactical` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:113` | `tactical` | `"san": ["DNS:tactical-node-alpha.mil", "IP:127.0.0.1", "TOR:alpha5739281.onion"],` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:128` | `tactical` | `print("  -> Issuing Tactical Node Bravo Certificate...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:132` | `tactical` | `"subject": "CN=tactical-node-bravo.mil,OU=Forward Base Bravo,O=Tactical P2P,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:133` | `sovereign` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:133` | `tactical` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:137` | `tactical` | `"san": ["DNS:tactical-node-bravo.mil", "IP:127.0.0.1", "TOR:bravo9184712.onion"],` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:155` | `sovereign` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:155` | `tactical` | `"issuer": "CN=Sovereign-Tactical-Issuing-CA-1,O=Sovereign Defense,C=US",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/generate_sovereign_pki.py:191` | `sovereign` | `"root_authority": "CN=Sovereign-Defense-Root-CA",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/generate_sovereign_pki.py:198` | `sovereign` | `print(f"[SUCCESS] Sovereign PKI generated successfully in {certs_dir}!")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/package_deployment.py:2` | `top secret` | `"""Build a clean TOP SECRET deployment tree.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/production_cleanup_utils.py:19` | `military-grade` | `'BEYOND MILITARY-GRADE',` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/production_cleanup_utils.py:21` | `revolutionary` | `'REVOLUTIONARY',` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/production_cleanup_utils.py:22` | `cutting-edge` | `'CUTTING-EDGE',` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/production_cleanup_utils.py:24` | `world-class` | `'WORLD-CLASS'` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_defense_audit.py:3` | `sovereign` | `Sovereign Transmit 2027 (ST2027) — Master Defense Audit Harness` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_defense_audit.py:5` | `sovereign` | `Comprehensive verification runner for military/sovereign evaluation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_defense_audit.py:116` | `zero-trust` | `f"{total_passed} tests passed ({passed_matches[0] if passed_matches else 0} lib incl. TPM 2.0 NV rollback guard, S-01...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:5` | `tactical` | `Master Phase 5 DoD CSRMC Operations Phase & Tactical DDIL Resilience Mission Drill Harness.` | (b) Standard Identifier | KEEP |
| `scripts/run_phase5_csrmc_operations_drill.py:6` | `mission-critical` | `Executes end-to-end operational verification across 5 mission-critical probes:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:75` | `tactical` | `"lifecycle_phase": "Phase 5: Operations Phase & Tactical Resilience",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:175` | `tactical` | `"""Probe 2: Tactical DDIL Comms Disruption & Merkle-DAG Delta Reconciliation."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:176` | `tactical` | `log.info("[PROBE 2/5] Simulating Tactical DDIL Contested Link Disruption...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:177` | `tactical` | `node_alpha = DDILNodeMesh(node_id="TACTICAL-ALPHA")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:178` | `tactical` | `node_bravo = DDILNodeMesh(node_id="TACTICAL-BRAVO")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:181` | `tactical` | `node_alpha.set_peer_connectivity("TACTICAL-BRAVO", False)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:182` | `tactical` | `node_bravo.set_peer_connectivity("TACTICAL-ALPHA", False)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:189` | `tactical` | `sender_id="TACTICAL-ALPHA",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:190` | `tactical` | `recipient_id="TACTICAL-BRAVO",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:201` | `tactical` | `sender_id="TACTICAL-ALPHA",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:202` | `tactical` | `recipient_id="TACTICAL-BRAVO",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:213` | `tactical` | `recipient_id="TACTICAL-BRAVO",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:222` | `tactical` | `recipient_id="TACTICAL-BRAVO",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:232` | `tactical` | `queued = node_alpha.outbound_store["TACTICAL-BRAVO"]` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:235` | `tactical` | `# Restore tactical link and reconcile deltas` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:236` | `tactical` | `node_alpha.set_peer_connectivity("TACTICAL-BRAVO", True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:237` | `tactical` | `node_bravo.set_peer_connectivity("TACTICAL-ALPHA", True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:239` | `tactical` | `delta = node_alpha.reconcile_with_peer("TACTICAL-BRAVO", set(node_bravo.delivered_bundles.keys()))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:245` | `tactical` | `delta2 = node_alpha.reconcile_with_peer("TACTICAL-BRAVO", set(node_bravo.delivered_bundles.keys()))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:274` | `tactical` | `sender_id="TACTICAL-ALPHA",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:275` | `tactical` | `recipient_id="TACTICAL-BRAVO",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:277` | `tactical` | `payload_plaintext=b"Tactical low-bandwidth telemetry message",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:290` | `tactical` | `payload_verified = (decrypted == b"Tactical low-bandwidth telemetry message")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase5_csrmc_operations_drill.py:300` | `tactical` | `"standard": "RFC 9172 BPsec / Tactical Edge Triad Architecture (TETA)",` | (b) Standard Identifier | KEEP |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py:5` | `tactical` | `Master Phase 6 CJADC2 Tactical Data Fabric & Dynamic PQC Crypto-Agility Mission Drill Harness.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py:6` | `mission-critical` | `Executes end-to-end operational verification across 5 mission-critical probes:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py:81` | `tactical` | `"lifecycle_phase": "Phase 6: Tactical Data Fabric, Cross-Domain MLS & Dynamic PQC Crypto-Agility",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py:199` | `top secret` | `# Vector 1: TOP SECRET dirty-word spillage into lower enclave` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py:200` | `top secret` | `spill_payload = b"TACTICAL UPDATE // TOP SECRET // SENSOR TRACK COORDINATES"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py:200` | `tactical` | `spill_payload = b"TACTICAL UPDATE // TOP SECRET // SENSOR TRACK COORDINATES"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py:359` | `tactical` | `# 1. Generate MIL-STD-6090 CoT tactical event` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/run_phase6_cjadc2_data_fabric_drill.py:459` | `tactical` | `parser = argparse.ArgumentParser(description="DoD CJADC2 Phase 6 Tactical Data Fabric Mission Drill")` | (b) Standard Identifier | KEEP |
| `scripts/setup_tor_overlay.sh:2` | `top secret` | `# setup_tor_overlay.sh — provision the local Tor overlay for TOP SECRET transport.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/setup_wireguard.ps1:1` | `sovereign` | `# setup_wireguard.ps1 — provision the sovereign WireGuard / private-APN path.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/setup_wireguard.sh:2` | `sovereign` | `# setup_wireguard.sh — provision the sovereign WireGuard / private-APN path.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/sign_dependencies.py:6` | `destroyer` | `custody path: ~/.destroyer-st2027/offline-keys/military_root_ca.pem` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/sign_dependencies.py:35` | `destroyer` | `DEFAULT_CA_DIR = Path.home() / ".destroyer-st2027" / "offline-keys"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/tor/secure-transmit-tor.service:2` | `sovereign` | `Description=Tor onion overlay for 2027 sovereign transmit pipeline (ts instance)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/tor/torrc.ts-hardened:1` | `top secret` | `# torrc.ts-hardened — hardened Tor client template for TOP SECRET transport.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/verify_50x_sovereign_superiority.py:24` | `sovereign` | `6. Zero Cloud Metadata & Sovereign P2P Independence` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/verify_50x_sovereign_superiority.py:156` | `sovereign` | `original_data = b"TOP-SECRET-SOVEREIGN-ORDER-2027:" + (b"B" * 4900) + b":TERMINATE"` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/verify_50x_sovereign_superiority.py:312` | `sovereign` | `print("ST2027: 50X SOVEREIGN DEFENSE SUPERIORITY EMPIRICAL VERIFICATION BENCHMARK")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/verify_50x_sovereign_superiority.py:339` | `sovereign` | `verdict = "50X SOVEREIGN DEFENSE SUPERIORITY MATHEMATICALLY & EMPIRICALLY CONFIRMED" if all_passed else "BENCHMARK DE...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `scripts/verify_ato_deployment_package.py:449` | `sovereign` | `"system_name": "Sovereign Military P2P Tactical Mesh (Destroyer-P2P)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/verify_ato_deployment_package.py:449` | `destroyer` | `"system_name": "Sovereign Military P2P Tactical Mesh (Destroyer-P2P)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/verify_ato_deployment_package.py:449` | `tactical` | `"system_name": "Sovereign Military P2P Tactical Mesh (Destroyer-P2P)",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/verify_host_hardening.py:16` | `classified` | `4. Radio Silence / RF Emission Discipline (WiFi / Bluetooth status on classified nodes)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/verify_host_hardening.py:271` | `classified` | `"""Verify RF Emission discipline / TEMPEST posture: wireless adapters disabled on classified nodes."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/verify_host_hardening.py:312` | `classified` | `"details": "Active RF wireless adapters detected! Prohibited on classified military networks.",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/wireguard/wg-ts0.conf.template:1` | `sovereign` | `# wg-ts0.conf.template — sovereign WireGuard / private-APN path template.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/wireguard/wg-ts0.conf.template:13` | `sovereign` | `# SCOPE: sovereign APN / private WireGuard transport for the 2027 pipeline.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/witnessed_key_ceremony.py:6` | `sovereign` | `Secure P2P Platform, establishing CNSA 2.0 sovereign root authority.` | (b) Standard Identifier | KEEP |
| `scripts/witnessed_key_ceremony.py:102` | `tactical` | `{"id": "CUSTODIAN-03", "role": "Enclave Operations Lead", "name": "Tactical Operations Gamma"},` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/witnessed_key_ceremony.py:243` | `classified` | `print("  [!] resistance or hardware attestation. Not valid for classified CSfC.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `scripts/witnessed_key_ceremony.py:261` | `sovereign` | `print("\n[*] Generating CNSA 2.0 Post-Quantum Sovereign Root Keys...")` | (b) Standard Identifier | KEEP |
| `scripts/witnessed_key_ceremony.py:270` | `sovereign` | `# 2. SLH-DSA-256f (FIPS 205) Stateless Hash-Based Sovereign Emergency Root` | (b) Standard Identifier | KEEP |
| `secure_enclave_key_storage.py:937` | `NC3` | `data: Bytes to sign (64-byte auth digests in the NC3 flow).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_enclave_key_storage.py:1178` | `zero-trust` | `"Enclave KEK seed persistence prohibited under military zero-trust policy. "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_file_transfer.py:6` | `tactical` | `over unreliable or adversarial tactical channels. Chunks are individually verified` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_key_manager.py:767` | `maximum security` | `# Use HKDF-SHA512 for maximum security (NIST Level 5+)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:133` | `sovereign` | `raise RuntimeError("SECURITY VIOLATION: External cloud discovery is strictly forbidden in sovereign military mode.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:1592` | `tactical` | `"""Create an ephemeral in-memory anonymous tactical identity (Zero disk storage)."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:1627` | `tactical` | `print(f"\n[PASS] Ephemeral Tactical Identity active: {username}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:1745` | `tactical` | `print("[INFO] Falling back to autonomous local tactical profile...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:1749` | `tactical` | `print("[INFO] Falling back to autonomous local tactical profile...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2120` | `maximum security` | `KEY_ROTATION_INTERVAL = 300  # 5 minutes for maximum security (was 3600)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2150` | `maximum security` | `"secure_enclave", "oauth_auth", "key_protection"],  # Maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2181` | `tactical` | `anonymous: Whether to run in pure anonymous tactical mode (default: False)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2185` | `sovereign` | `# CNSA 2.0 / TOP SECRET Sovereign Mode Enforcement` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:2185` | `top secret` | `# CNSA 2.0 / TOP SECRET Sovereign Mode Enforcement` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:2190` | `sovereign` | `log.info("[CNSA 2.0] Strict sovereign military mode active — bare-metal Rust engine and hardware root-of-trust armed.")` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:2192` | `sovereign` | `# Tactical Sovereign Data Plane Attributes (destroyer_tactical_p2p parity)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2192` | `tactical` | `# Tactical Sovereign Data Plane Attributes (destroyer_tactical_p2p parity)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2257` | `nuclear command` | `# NC3 Nuclear Command & Control (EAM / PAL) subsystem state` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2257` | `nuclear` | `# NC3 Nuclear Command & Control (EAM / PAL) subsystem state` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2257` | `NC3` | `# NC3 Nuclear Command & Control (EAM / PAL) subsystem state` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2259` | `nuclear` | `self.enable_nc3_default = True  # Every message is NC3 nuclear-grade by default` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2259` | `NC3` | `self.enable_nc3_default = True  # Every message is NC3 nuclear-grade by default` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `secure_p2p.py:2509` | `maximum security` | `# Enforce maximum security with no fallbacks` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2538` | `maximum security` | `print("Maximum security mode activated - no fallbacks permitted")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2539` | `maximum security` | `print("MAXIMUM SECURITY ACHIEVED - All components integrated")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2581` | `tactical` | `# Initialize CSRMC Phase 5 Operations and Tactical Resilience Engines` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2605` | `tactical` | `log.info("[CSRMC] Tactical DDIL mesh store-and-forward router linked to SecureP2PChat")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2739` | `maximum security` | `"""Enforce maximum security requirements with no fallbacks."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2748` | `maximum security` | `secure_p2p_logger.info("Enforcing maximum security requirements...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2753` | `maximum security` | `# If we reach here, maximum security is achieved` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2754` | `maximum security` | `print("[PASS] MAXIMUM SECURITY ACHIEVED")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2759` | `maximum security` | `# Update security hardening status to reflect maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2796` | `maximum security` | `secure_p2p_logger.critical(f"Maximum security module not available: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2798` | `maximum security` | `"Maximum security enforcement not available",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2803` | `maximum security` | `secure_p2p_logger.critical(f"Maximum security enforcement failed: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:2805` | `maximum security` | `f"Maximum security enforcement failed: {e}",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:3725` | `sovereign` | `"in 2027+ Defense Production mode (SECURE_P2P_PRODUCTION=true). Sovereign Mutual ML-DSA-87 authentication is mandatory."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:3729` | `sovereign` | `"MILITARY FATAL: Commercial cloud OAuth is prohibited in sovereign production mode. "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:3730` | `sovereign` | `"Sovereign Mutual ML-DSA-87 certificate authentication is mandatory."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:3779` | `sovereign` | `log.info("User authentication is ENFORCED via Sovereign Mutual ML-DSA-87 Certificates (P2P_REQUIRE_AUTH=true).")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4160` | `tactical` | `"""Enhanced startup flow with user management, anonymous tactical mode, and automatic login."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4163` | `tactical` | `print("[SECURE] ST2027 SECURE TACTICAL COMMUNICATIONS SYSTEM", flush=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4164` | `zero-trust` | `print("   Quantum-Resistant \| Hardware-Secured \| Zero-Trust", flush=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4171` | `tactical` | `print(f"\n[ANONYMOUS] Anonymous Tactical Mode Active: {self.local_username}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4186` | `tactical` | `print("[WARN] Local profile unlock failed. Starting in Anonymous Tactical Mode.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4216` | `tactical` | `# 3. First-time setup: Choose between Anonymous Tactical Mode vs Persistent Disk Profile` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4231` | `tactical` | `print(" 1. [RECOMMENDED] Pure Anonymous Tactical Mode (Store Nothing - In-Memory Only)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4248` | `tactical` | `callsign = (await self._async_input("Enter tactical callsign (or press Enter for random Ghost-xxxx): ")).strip()` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4570` | `zero-trust` | `"military zero-trust policy.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4671` | `zero-trust` | `f"or whitelist pre-authorization before key pinning under military zero-trust policy."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:4866` | `NC3` | `log.warning(f"NC3 war key unavailable at session setup: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:5848` | `tactical` | `"Tactical Private APN (P2P_TACTICAL_APN=true), or Multi-Hop Onion Router (P2P_MULTIHOP_ROUTING=true) "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:5879` | `tactical` | `# Enforce tactical network cloaking policy (prohibit unencapsulated public egress)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:5884` | `tactical` | `log.critical(f"Tactical network cloaking violation: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:5885` | `tactical` | `raise SecurityError(f"Connection to [{peer_ip}]:{peer_port} prohibited by tactical cloaking: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:6147` | `sovereign` | `log.info("Mutual ML-DSA-87 certificate authentication active (Sovereign mode).")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:6148` | `sovereign` | `print(f"\033[92mMutual ML-DSA-87 certificate authentication active (Sovereign mode)\033[0m")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:6647` | `tactical` | `# Enforce tactical network cloaking policy on inbound ingress` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:6652` | `tactical` | `log.warning(f"Inbound connection from {client_ip} rejected by tactical cloaking: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:6975` | `sovereign` | `log.info("Mutual ML-DSA-87 certificate authentication verified for incoming connection (Sovereign mode).")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7283` | `nuclear command` | `# INSECURE NON-EAM REJECTION UNDER NUCLEAR COMMAND POLICY` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7283` | `nuclear` | `# INSECURE NON-EAM REJECTION UNDER NUCLEAR COMMAND POLICY` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7290` | `nuclear` | `f"Insecure Normal Chat / Critical message from {sender} rejected under Universal Nuclear EAM Policy (sha384:{_digest}...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7295` | `nuclear` | `print(f"\n{BOLD}{RED}[NC3 SECURITY VIOLATION] Insecure Normal Chat / Critical Message from {sender} REJECTED fail-clo...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7295` | `NC3` | `print(f"\n{BOLD}{RED}[NC3 SECURITY VIOLATION] Insecure Normal Chat / Critical Message from {sender} REJECTED fail-clo...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7296` | `NC3` | `print(f"{BOLD}{RED}[NC3-EAM]{RESET} {CYAN}{self.local_username}: {RESET}", end='', flush=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7323` | `NC3` | `print(f"{BOLD}{RED}[NC3-EAM]{RESET} {CYAN}{self.local_username}: {RESET}", end='', flush=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7342` | `NC3` | `print(f"\n{RED}[NC3 SECURITY VIOLATION] EMERGENCY REJECTION: EAM rejected from peer '{self.peer_username}' because pe...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7352` | `nuclear` | `if directive in ("NC3-NUCLEAR-EAM", "NC3-TACTICAL-CHAT", "NC3-TACTICAL-EAM", "FLASH-TACTICAL-ORDER"):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7352` | `NC3` | `if directive in ("NC3-NUCLEAR-EAM", "NC3-TACTICAL-CHAT", "NC3-TACTICAL-EAM", "FLASH-TACTICAL-ORDER"):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7352` | `tactical` | `if directive in ("NC3-NUCLEAR-EAM", "NC3-TACTICAL-CHAT", "NC3-TACTICAL-EAM", "FLASH-TACTICAL-ORDER"):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7361` | `top secret` | `print(f"  TOP SECRET // SI-OP-IA // NC3 // NOFORN")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7361` | `NC3` | `print(f"  TOP SECRET // SI-OP-IA // NC3 // NOFORN")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7374` | `sovereign` | `print(f"  [STAGE 5: WIRE TRANSPORT]     {GREEN}VERIFIED{RESET} -> P2P Mutual TLS 1.3 Transport Active with Sovereign ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7377` | `NC3` | `print(f"{BOLD}{RED}[NC3-EAM]{RESET} {CYAN}{self.local_username}: {RESET}", end='', flush=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7385` | `NC3` | `print(f"\n{RED}[NC3 SECURITY VIOLATION] EAM rejected fail-closed: {e_verify}{RESET}\n")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7386` | `NC3` | `print(f"{BOLD}{RED}[NC3-EAM]{RESET} {CYAN}{self.local_username}: {RESET}", end='', flush=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7388` | `NC3` | `# Explicit Strategic EAM (e.g. FLASH-DEFCON-1 via /nc3-send): requires manual /nc3-verify` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7392` | `NC3` | `print(f"  [CRITICAL NC3 ALERT] INCOMING EMERGENCY ACTION MESSAGE (EAM) DETECTED!")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7394` | `top secret` | `print(f"  VALIDITY WINDOW: {validity}s \| LEVEL: DEFCON-1 TOP SECRET // SI-OP-IA")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7396` | `NC3` | `print(f"  EXECUTE: /nc3-verify (or /nc3_verify)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7398` | `NC3` | `print(f"{BOLD}{RED}[NC3-EAM]{RESET} {CYAN}{self.local_username}: {RESET}", end='', flush=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:7402` | `NC3` | `f"NC3 EAM RECEIVED: {eam_id} [Directive: {directive}] Awaiting Dual Custody.",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8139` | `sovereign` | `log.info("Mutual ML-DSA-87 certificate authentication verified for incoming connection (Sovereign mode).")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8392` | `destroyer` | `salt=b"destroyer-p2p-rust-v1",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8393` | `destroyer` | `info=b"destroyer/frame/v1",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8512` | `nuclear` | `# Insecure plain and legacy critical MSG format strictly prohibited under Universal Nuclear EAM Policy` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8513` | `nuclear` | `return _deny("FAIL-CLOSED SECURITY VIOLATION: Insecure plain or critical MSG format prohibited under Universal Nuclea...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8515` | `NC3` | `# Internal NC3 Emergency Action Message payload` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8517` | `NC3` | `return _deny("NC3 message exceeds maximum permitted transfer size")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8791` | `top secret` | `print(f"  TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND COMMUNICATIONS ACTIVE")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8791` | `nuclear command` | `print(f"  TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND COMMUNICATIONS ACTIVE")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8791` | `nuclear` | `print(f"  TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND COMMUNICATIONS ACTIVE")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8791` | `NC3` | `print(f"  TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND COMMUNICATIONS ACTIVE")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8803` | `NC3` | `log.warning(f"NC3 war key unavailable at session setup: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8911` | `nuclear` | `# Universal Nuclear EAM Enforcement (DoD Directive S-5210.41M / NC3)` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:8911` | `NC3` | `# Universal Nuclear EAM Enforcement (DoD Directive S-5210.41M / NC3)` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:8922` | `nuclear` | `print(f"{RED}Failed to encrypt nuclear EAM message. Please try again.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8928` | `nuclear` | `print(f"{RED}Failed to encrypt nuclear EAM message. Please try again.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8931` | `nuclear` | `# Universal Nuclear EAM rule: Excluded from persistent message history` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8937` | `nuclear` | `log.warning("Failed to send nuclear EAM message, connection may be lost")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:8969` | `nuclear` | `log.error(f"Failed to send nuclear EAM message: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:9062` | `tactical` | `In high-threat or tactical cloaking mode (P2P_TACTICAL_CLOAK=1), inter-arrival` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:9323` | `maximum security` | `self._canary_check_interval = self.CANARY_CHECK_INTERVAL  # Check every 10 seconds for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:9375` | `maximum security` | `# Check every canary check interval for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10206` | `top secret` | `print(f"  TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND COMMUNICATIONS ACTIVE")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10206` | `nuclear command` | `print(f"  TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND COMMUNICATIONS ACTIVE")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10206` | `nuclear` | `print(f"  TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND COMMUNICATIONS ACTIVE")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10206` | `NC3` | `print(f"  TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND COMMUNICATIONS ACTIVE")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10221` | `nuclear` | `print(f"  {BOLD}/nc3-send{RESET} - Transmit nuclear Emergency Action Message under Two-Person Rule")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10221` | `NC3` | `print(f"  {BOLD}/nc3-send{RESET} - Transmit nuclear Emergency Action Message under Two-Person Rule")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10222` | `NC3` | `print(f"  {BOLD}/nc3-verify{RESET} - Dual-authenticate and unseal pending Emergency Action Message")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10223` | `NC3` | `print(f"  {BOLD}/eam <text>{RESET} - Issue high-priority NC3 directive under Two-Person Rule")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10224` | `nuclear` | `print(f"  {BOLD}/nuclear <text>{RESET} - Alias for /eam nuclear-grade command transmission")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10225` | `sovereign` | `print(f"  {BOLD}/zgdp{RESET} - Display Sovereign Zero-Gap Defense Pipeline telemetry")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10231` | `tactical` | `print(f"  {BOLD}/silence{RESET} - Toggle tactical network cloak and background chaff")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10238` | `tactical` | `print(f"  {BOLD}/diode-tx <ip> <port> <msg>{RESET} - Send simplex message over tactical data diode (MDS FEC)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10239` | `tactical` | `print(f"  {BOLD}/diode-rx [ip] <port> [timeout]{RESET} - Receive simplex message from tactical data diode")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `secure_p2p.py:10271` | `top secret` | `print(f"  Security Classification   : {BOLD}{RED}TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10271` | `nuclear command` | `print(f"  Security Classification   : {BOLD}{RED}TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10271` | `nuclear` | `print(f"  Security Classification   : {BOLD}{RED}TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10271` | `NC3` | `print(f"  Security Classification   : {BOLD}{RED}TOP SECRET // SI-OP-IA // NC3 NUCLEAR COMMAND{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10362` | `sovereign` | `print(f"  Auth Mechanism: {GREEN}Sovereign Mutual ML-DSA-87 Certificate Pinning (OAuth disabled){RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10418` | `NC3` | `elif cmd in ('/nc3-send', '/nc3_send'):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10421` | `NC3` | `print(f"\n{RED}[NC3 ERROR] Cannot dispatch EAM: Not connected to peer node.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10427` | `top secret` | `print(f"  TOP SECRET // SI-OP-IA // NC3 // NOFORN")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10427` | `NC3` | `print(f"  TOP SECRET // SI-OP-IA // NC3 // NOFORN")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10432` | `NC3` | `# Check if arguments provided via command line (e.g. /nc3-send <directive> <target> <pal>)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10449` | `NC3` | `print(f"\n{RED}[NC3 ERROR] Incomplete parameters. EAM generation aborted.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10457` | `NC3` | `print(f"{CYAN}[NC3] Authenticating Dual Custodian Officers...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10472` | `NC3` | `print(f"\n{RED}[NC3 ERROR] War-order key must be 32 bytes (64 hex). EAM aborted.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10495` | `NC3` | `print(f"\n{BOLD}{GREEN}[NC3 DISPATCH SUCCESS] EMERGENCY ACTION MESSAGE BROADCAST!{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10510` | `NC3` | `print(f"\n{RED}[NC3 DISPATCH FAILURE] Could not dispatch EAM: {e_send_eam}{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10511` | `NC3` | `log.error(f"NC3 dispatch failure: {e_send_eam}", exc_info=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10515` | `NC3` | `elif cmd in ('/nc3-verify', '/nc3_verify'):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10518` | `NC3` | `print(f"\n{YELLOW}[NC3 NOTICE] No pending Emergency Action Message (EAM) in buffer to verify.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10523` | `top secret` | `print(f"  TOP SECRET // SI-OP-IA // NC3 // NOFORN")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10523` | `NC3` | `print(f"  TOP SECRET // SI-OP-IA // NC3 // NOFORN")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10545` | `NC3` | `print(f"{CYAN}[NC3] Validating Recipient Dual Custody Credentials...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10557` | `NC3` | `print(f"{YELLOW}[NC3] Executing Constant-Time Dual Post-Quantum Verification...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10560` | `NC3` | `print(f"\n{RED}[NC3 VERIFICATION FAILED] EMERGENCY REJECTION: war-order key required.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10600` | `NC3` | `print(f"\n{RED}[NC3 VERIFICATION FAILED] EMERGENCY REJECTION: {e_verify_eam}{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10601` | `NC3` | `log.error(f"NC3 verification failed: {e_verify_eam}", exc_info=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10765` | `top secret` | `print(f"  TOP SECRET // SI-OP-IA // KMI AIR-GAPPED KEY-FILL IMPORT")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10825` | `NC3` | `print(f"  {GREEN}[+] Injected verified 256-bit NC3 war-order authentication key.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10865` | `nuclear` | `elif cmd in ('/eam', '/nuclear'):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10876` | `NC3` | `print(f"{RED}[NC3 DIRECTIVE ERROR] Execution failed: {e_eam}{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:10877` | `NC3` | `log.error(f"NC3 directive failure: {e_eam}", exc_info=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11108` | `top secret` | `print(f"  TOP SECRET // SI-OP-IA // ENDPOINT HOST DEFENSE POSTURE AUDIT")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11266` | `tactical` | `print(f"\n{BOLD}{YELLOW}[TACTICAL ROUTING] Tactical Cloak: DISENGAGED{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11270` | `tactical` | `print(f"\n{BOLD}{GREEN}[TACTICAL ROUTING] Tactical Cloak: ENGAGED{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11274` | `tactical` | `print(f"\n{RED}Error toggling tactical cloak: {e}{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11322` | `tactical` | `print(f"  Tactical Cloak Enforced:  {GREEN if tactical_cloak_enabled() else YELLOW}{tactical_cloak_enabled()}{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11386` | `tactical` | `print(f"  {BOLD}TRAFFIC FLOW CONFIDENTIALITY & TACTICAL CLOAKING{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11426` | `zero-trust` | `# Zero-Trust Military Posture: Verify peer is authenticated and verified` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11430` | `zero-trust` | `f"ZERO-TRUST REJECTION: File message rejected from unverified peer '{self.peer_username}' "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11968` | `NC3` | `"NC3 custodian identities are not loaded; production EAM "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11975` | `nuclear` | `officer_ids[0], "GEN", "Strategic Nuclear Controller",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11979` | `nuclear` | `officer_ids[1], "ADM", "Executive Nuclear Custodian",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11986` | `NC3` | `"NC3 production requires two separately provisioned "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11994` | `NC3` | `"NC3 custodians generated in-process for lab/drill use only; "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:11998` | `nuclear` | `officer_ids[0], "GEN", "Strategic Nuclear Controller"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12001` | `nuclear` | `officer_ids[1], "ADM", "Executive Nuclear Custodian"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12005` | `nuclear` | `"""Derives a deterministic 32-byte NC3 nuclear-grade war key from the authenticated hybrid root key."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12005` | `NC3` | `"""Derives a deterministic 32-byte NC3 nuclear-grade war key from the authenticated hybrid root key."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12018` | `NC3` | `"NC3 war key provisioning invalid: P2P_NC3_WAR_KEY is not "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12023` | `NC3` | `"NC3 war key provisioning invalid: P2P_NC3_WAR_KEY must be "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12038` | `NC3` | `salt=b"SecureP2P::NC3::NuclearMessage::WarKey::v1::CNSA2-Level5",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12039` | `nuclear` | `info=b"NC3/EAM-AUTOMATIC-NUCLEAR-SESSION-KEY-V1"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12039` | `NC3` | `info=b"NC3/EAM-AUTOMATIC-NUCLEAR-SESSION-KEY-V1"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12046` | `nuclear` | `# every peer on earth -- forbidden for nuclear traffic.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12048` | `NC3` | `"NC3 war key unavailable: an authenticated hybrid root key or "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12054` | `NC3` | `Seals a chat message inside a full DoD Directive S-5210.41M / NC3 Emergency Action Message container.` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:12065` | `NC3` | `directive_code="NC3-TACTICAL-CHAT",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12065` | `tactical` | `directive_code="NC3-TACTICAL-CHAT",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12077` | `NC3` | `Verifies and unseals an incoming NC3 Emergency Action Message.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12083` | `NC3` | `war key via canonical nc3 _pal_decrypt (AES primary, no ChaCha seal).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12172` | `NC3` | `# NC3 opener (AES-256-GCM primary; seal/open symmetry guaranteed by` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12656` | `nuclear command` | `"Nuclear Command (NC3)": "[OK] Two-Person Rule + Dual ML-DSA-87 + 120s Window",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12656` | `nuclear` | `"Nuclear Command (NC3)": "[OK] Two-Person Rule + Dual ML-DSA-87 + 120s Window",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12656` | `NC3` | `"Nuclear Command (NC3)": "[OK] Two-Person Rule + Dual ML-DSA-87 + 120s Window",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12914` | `maximum security` | `security warnings and ensure maximum security for their application.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12932` | `maximum security` | `print(" [OK] Hardware DEP is enabled (Maximum security)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12956` | `maximum security` | `print("   - Recommendation: Run this application as administrator for maximum security")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:12999` | `maximum security` | `print(" [OK] Using maximum security settings")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13001` | `maximum security` | `print(" [WARN] Not using maximum security settings")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13026` | `maximum security` | `print("Run this application with administrator privileges for maximum security.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13731` | `sovereign` | `# TACTICAL MILITARY SOVEREIGN DATA PLANE METHODS (destroyer_tactical_p2p PARITY)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13731` | `tactical` | `# TACTICAL MILITARY SOVEREIGN DATA PLANE METHODS (destroyer_tactical_p2p PARITY)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13735` | `tactical` | `"""Initialize tactical key storage and working directories."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13924` | `NC3` | `raise ValueError("NC3 directive payload must be a JSON dictionary")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13929` | `NC3` | `print(f"\n{BOLD}{RED}[{name} NC3 SECURITY VIOLATION] Directive dropped: Two-Person Rule unverified ({two_person}){RES...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13933` | `NC3` | `print(f"\n{BOLD}{RED}[{name} NC3 SECURITY VIOLATION] Directive dropped: Temporal expiration guard (expired){RESET}\n[...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13935` | `top secret` | `print(f"\n{BOLD}{RED}[{name} TOP SECRET NC3/EAM DIRECTIVE RECEIVED]{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13935` | `NC3` | `print(f"\n{BOLD}{RED}[{name} TOP SECRET NC3/EAM DIRECTIVE RECEIVED]{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13943` | `NC3` | `print(f"\n{BOLD}{RED}[{name} NC3 SECURITY FAULT] Malformed NC3 directive rejected: {exc}{RESET}\n[{name}] > ", end=""...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13949` | `tactical` | `print(f"\n{BOLD}{GREEN}[{name} INCOMING ZERO-GAP TACTICAL MESSAGE]{RESET} {BOLD}{msg_decoded}{RESET}\n[{name}] > ", e...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13957` | `tactical` | `print(f"\n{BOLD}{YELLOW}[{name} TACTICAL COT BEACON RECEIVED]{RESET} {cot_json}\n[{name}] > ", end="", flush=True)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13959` | `tactical` | `print(f"\n{BOLD}{GREEN}[{name} INCOMING TACTICAL MESSAGE]{RESET} {BOLD}{payload}{RESET}\n[{name}] > ", end="", flush=...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:13992` | `NC3` | `"""Transmit an authentic NC3 Universal Emergency Action Message (EAM) under Two-Person Integrity."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14007` | `NC3` | `print(f"{RED}[EAM REFUSED] Two-Person Rule cannot be verified on the paced console path in production; use the NC3 cr...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14025` | `nuclear command` | `print(f"{BOLD}{MAGENTA}[EAM RELEASED] NC3 Nuclear Command Directive sealed and queued into 15ms wire pacing.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14025` | `nuclear` | `print(f"{BOLD}{MAGENTA}[EAM RELEASED] NC3 Nuclear Command Directive sealed and queued into 15ms wire pacing.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14025` | `NC3` | `print(f"{BOLD}{MAGENTA}[EAM RELEASED] NC3 Nuclear Command Directive sealed and queued into 15ms wire pacing.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14032` | `tactical` | `"""Send a signed Cursor-on-Target (CoT) tactical situational awareness event in-band."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14135` | `sovereign` | `# DESTROYER-ST2027: PRIMARY SOVEREIGN MILITARY TACTICAL ENTRY POINT` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14135` | `destroyer` | `# DESTROYER-ST2027: PRIMARY SOVEREIGN MILITARY TACTICAL ENTRY POINT` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14135` | `tactical` | `# DESTROYER-ST2027: PRIMARY SOVEREIGN MILITARY TACTICAL ENTRY POINT` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14138` | `top secret` | `# Classification: TOP SECRET // NC3 STRATEGIC DEFENSE DIRECTIVE // NOFORN` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14138` | `NC3` | `# Classification: TOP SECRET // NC3 STRATEGIC DEFENSE DIRECTIVE // NOFORN` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14140` | `zero-trust` | `# Real-Time Monitoring: DoD cATO Active Cyber Defense + Continuous Zero-Trust` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:14193` | `classified` | `# NSA RTB Classified Indicator / Dirty-Word Filter` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:14195` | `top secret` | `b"top secret",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14204` | `classified` | `"""Constant-time traversal checking for classified indicators."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14244` | `sovereign` | `[TOP SECRET // CNSA 2.0 // NOFORN // SOVEREIGN MILITARY DATA PLANE]` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:14244` | `top secret` | `[TOP SECRET // CNSA 2.0 // NOFORN // SOVEREIGN MILITARY DATA PLANE]` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:14251` | `sovereign` | `SECURITY POSTURE: Sovereign Military Enclave / CNSA 2.0 L5 Hybrid / Native Rust` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:14256` | `tactical` | `"""Unified Military Tactical P2P Node orchestrating KEX, Paced Channel, and Diode."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14527` | `NC3` | `salt=b"NC3-WAR-KEY-SALT-v1",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14528` | `NC3` | `info=b"NC3-WAR-ORDER-PAL-KEY-DERIVATION-v1",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14688` | `top secret` | `print(f"\n{BOLD}{RED}[TOP SECRET NC3 // DEFCON-1 NUCLEAR EAM VERIFIED UNDER DUAL CUSTODY]{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14688` | `nuclear` | `print(f"\n{BOLD}{RED}[TOP SECRET NC3 // DEFCON-1 NUCLEAR EAM VERIFIED UNDER DUAL CUSTODY]{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14688` | `NC3` | `print(f"\n{BOLD}{RED}[TOP SECRET NC3 // DEFCON-1 NUCLEAR EAM VERIFIED UNDER DUAL CUSTODY]{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14705` | `NC3` | `print(f"\n{BOLD}{RED}[{self.name} NC3 SECURITY FAULT] EAM Verification Rejected: {nce}{RESET}\n[{self.name}] > ", end...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14710` | `tactical` | `# Check for in-band tactical document transfer` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14769` | `tactical` | `print(f"\n{BOLD}{CYAN}[{self.name} TACTICAL CONTROL] Synchronized CER epoch rotation with peer. Advanced to Epoch #{n...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14771` | `tactical` | `print(f"\n{BOLD}{YELLOW}[{self.name} TACTICAL CONTROL] Ignored out-of-sequence epoch sync: {target_epoch} (current: {...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14832` | `tactical` | `print(f"\n{color}{BOLD}[{self.name} TACTICAL RADIO - {prec_name} // {clr} // {cav}]{RESET}\n  >> {BOLD}{mtext}{RESET}...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14857` | `tactical` | `print(f"\n{MAGENTA}{BOLD}[{self.name} PTT VOICE RX]{RESET} Tactical voice burst from {BOLD}{psigner}{RESET} ({pchunks...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14872` | `tactical` | `print(f"\n{BOLD}{GREEN}[{self.name} INCOMING ZERO-GAP TACTICAL MESSAGE]{RESET} {BOLD}{msg_decoded}{RESET}\n[{self.nam...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14890` | `zero-trust` | `print(f"\n{BOLD}{RED}[{self.name} ZERO-TRUST BREACH] Continuous verification failure: {zte}. Emergency zeroization.{R...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14917` | `zero-trust` | `print(f"\n{BOLD}{RED}[{self.name} ZERO-TRUST BREACH] Unsealed payload breached threshold: {zte}. Emergency zeroizatio...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14984` | `nuclear` | `# NC3 Two-Person Safety Gate: block single-officer strategic nuclear orders in routine chat` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14984` | `NC3` | `# NC3 Two-Person Safety Gate: block single-officer strategic nuclear orders in routine chat` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14990` | `nuclear` | `for kw in [b"launch code", b"nuclear strike", b"defcon 1", b"emergency action message", b"nuclear release", b"weapons...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14996` | `nuclear` | `print(f"{RED}[{self.name} NC3 SAFETY GATE] BLOCKED: Routine chat cannot convey strategic nuclear directive: '{indicat...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:14996` | `NC3` | `print(f"{RED}[{self.name} NC3 SAFETY GATE] BLOCKED: Routine chat cannot convey strategic nuclear directive: '{indicat...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15001` | `classified` | `# NSA RTB Classified Spillage Gate` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:15004` | `classified` | `print(f"{RED}[{self.name} RTB SPILLAGE] BLOCKED: Detected classified indicator '{spillage}' in {getattr(self, 'cleara...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15022` | `tactical` | `"""Transmit sensitive tactical mission document in-band across paced cells with SHA-384 integrity."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15049` | `NC3` | `"""Transmit authentic NC3 DEFCON-1 Emergency Action Message under Two-Person Integrity (ML-DSA-87)."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15082` | `NC3` | `print(f"{CYAN}[{self.name} NC3 DUAL CUSTODY] Two-Person Rule Authentication in Progress...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15102` | `nuclear` | `print(f"{BOLD}{MAGENTA}[{self.name} NC3 EAM RELEASED] Dual ML-DSA-87 signed nuclear order queued into wire pacing.{RE...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15102` | `NC3` | `print(f"{BOLD}{MAGENTA}[{self.name} NC3 EAM RELEASED] Dual ML-DSA-87 signed nuclear order queued into wire pacing.{RE...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15112` | `classified` | `"""Transmit priority-stamped, MLS-classified military telegram with RTB spillage prevention."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15124` | `classified` | `print(f"{RED}[{self.name} RTB SPILLAGE REJECTED] Refusing outbound message containing classified indicator '{spill}' ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15141` | `tactical` | `"""Transmit simulated quantized tactical voice frame burst across wire-camouflaged cells."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15156` | `tactical` | `print(f"\n{BOLD}{GREEN}=== BLUE FORCE TRACKING (BFT) / TACTICAL SITUATIONAL AWARENESS: {self.name} ==={RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15169` | `tactical` | `print(f"\n{BOLD}{CYAN}--- TACTICAL SITREP: {self.name} [{self.role.upper()}] ---{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15180` | `zero-trust` | `print(f"  Zero-Trust Score   : {self.zt_engine.trust_score(self.peer_addr)}/100 [Continuous Evaluation]")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15185` | `tactical` | `"""Send a signed Cursor-on-Target (CoT) tactical situational awareness event in-band."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15354` | `tactical` | `print(f"{BOLD}{CYAN}[{self.name} TACTICAL REKEY] CER Epoch rotated to #{new_epoch}. "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15458` | `tactical` | `print(f"{RED}[{self.name} MESH ERROR] Tactical DDIL Mesh Engine inactive.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15480` | `tactical` | `print(f"{YELLOW}[{self.name}] DDIL Tactical Mesh: INACTIVE{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15513` | `zero-trust` | `"""Display continuous Zero-Trust evaluation score and policy enforcement."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15515` | `zero-trust` | `print(f"{YELLOW}[{self.name}] Zero-Trust Engine: INACTIVE{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15521` | `zero-trust` | `{BOLD}[CONTINUOUS ZERO-TRUST POSTURE: {self.name}]{RESET}` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15552` | `zero-trust` | `Zero-Trust Engine : {"ARMED (Score: " + str(self.zt_engine.trust_score(self.peer_addr)) + "/100)" if self.zt_engine e...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15622` | `tactical` | `"""Run an interactive military tactical terminal."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15749` | `tactical` | `("/sitrep", "Display tactical station operational situation report"),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15753` | `zero-trust` | `("/trust", "Display Continuous Zero-Trust evaluation score (0-100)"),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15766` | `NC3` | `("/nc3-verify", "[LAB ONLY] Inspect last simulated NC3 EAM directive"),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15767` | `tactical` | `("/ptt", "[LAB ONLY] Transmit simulated 1.5s tactical voice burst"),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15772` | `tactical` | `print(f"\n{BOLD}{GREEN}*** TACTICAL SECURE CHANNEL ESTABLISHED (DEFCON-1) ***{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15777` | `NC3` | `print(f"  {YELLOW}[PRODUCTION] Simulated NC3/EAM/PTT surfaces are disabled.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15796` | `NC3` | `print("  [PRODUCTION] Simulated NC3/EAM/PTT surfaces are disabled.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15800` | `tactical` | `{BOLD}[TACTICAL NODE STATUS: {name}]{RESET}` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15904` | `nuclear` | `elif msg.startswith("/eam ") or msg.startswith("/nuclear "):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15925` | `NC3` | `elif msg in ("/nc3-verify", "/verify-eam"):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15927` | `NC3` | `_refuse_simulated("/nc3-verify")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15931` | `NC3` | `{BOLD}[LAST VERIFIED NC3 EAM DIRECTIVE]{RESET}` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15939` | `NC3` | `print(f"{YELLOW}No verified NC3 EAM in current session.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:15951` | `sovereign` | `print("  LAUNCHING FULL SOVEREIGN MILITARY P2P AUTOMATED DRILL")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16054` | `NC3` | `print(f"\n[*] Executing Live Two-Person Integrity NC3 EAM Transfer...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16067` | `NC3` | `print(f"{BOLD}{GREEN}[+] NC3 DEFCON-1 TWO-PERSON INTEGRITY ML-DSA-87 VERIFICATION CONFIRMED!{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16082` | `tactical` | `print(f"{BOLD}{GREEN}[+] MMHS TACTICAL FLASH TELEGRAM TRANSMISSION CONFIRMED!{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16099` | `sovereign` | `print("  [VERDICT] SOVEREIGN TOP SECRET STRATEGIC COMMUNICATIONS SYSTEM FULLY OPERATIONAL")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16099` | `top secret` | `print("  [VERDICT] SOVEREIGN TOP SECRET STRATEGIC COMMUNICATIONS SYSTEM FULLY OPERATIONAL")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16370` | `top secret` | `msg = b"TOP SECRET // NC3 SELFTEST"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16370` | `NC3` | `msg = b"TOP SECRET // NC3 SELFTEST"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16407` | `nuclear` | `plaintext = b"ST2027 SELFTEST // NORMAL MESSAGE MUST GET NUCLEAR-GRADE PROTECTION"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16484` | `tactical` | `"""Ensure tactical military credentials exist with owner-only permissions."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16600` | `sovereign` | `DESTROYER ST2027 — SOVEREIGN DEFENSE COMMAND (CNSA 2.0 / DEFCON-1)` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:16600` | `destroyer` | `DESTROYER ST2027 — SOVEREIGN DEFENSE COMMAND (CNSA 2.0 / DEFCON-1)` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:16605` | `tactical` | `[1] BASE ALPHA (NORAD) — Start Tactical Responder Node (Port 9060)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16606` | `tactical` | `[2] BASE BRAVO (PENTAGON) — Start Tactical Initiator Node (Target: [{def_ipv6}]:9060)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16639` | `destroyer` | `description="Destroyer ST2027 — CNSA 2.0 L5 tactical P2P node"` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:16639` | `tactical` | `description="Destroyer ST2027 — CNSA 2.0 L5 tactical P2P node"` | (b) Standard Identifier | KEEP |
| `secure_p2p.py:16676` | `tactical` | `p_node = sub.add_parser("node", help="Run the production tactical node")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16731` | `tactical` | `p_web = sub.add_parser("web", help="[LAB ONLY] Tactical web console")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_p2p.py:16757` | `destroyer` | `from destroyer import run_master_defense_audit` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `secure_p2p.py:16880` | `tactical` | `# tactical console, etc.) is NOT part of the production network entry point.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1111` | `top secret` | `classical-only by default and are refused for TOP SECRET.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1845` | `top secret` | `# TOP SECRET: full hardware-layer preflight (FIPS provider, hardware` | (b) Standard Identifier | KEEP |
| `secure_transmit_2027.py:1850` | `top secret` | `# TOP SECRET: OS & execution-runtime preflight (component #2:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1854` | `top secret` | `# TOP SECRET ephemeral profile (#5): no plaintext secrets, pins, or` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1909` | `top secret` | `"""Dual-control gate for TOP SECRET movement (SPO/DPO, zero compromise).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1911` | `top secret` | `TS and production postures handle TOP SECRET only and demand a valid` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1920` | `top secret` | `want = (classification or ("TOP SECRET" if (ts_mode or prod_mode) else "SECRET"))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1922` | `top secret` | `if ts_mode and norm != "TOP SECRET":` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `secure_transmit_2027.py:1923` | `top secret` | `raise SecurityError("TS mode handles TOP SECRET only")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1924` | `top secret` | `if norm not in ("SECRET", "TOP SECRET"):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1927` | `top secret` | `if ts_mode or (prod_mode and norm == "TOP SECRET"):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1984` | `top secret` | `# TOP SECRET posture: a missing (or undeterminable) TS-required` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1986` | `top secret` | `# only printed the advisory table, so a TOP SECRET session could run` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:1995` | `top secret` | `"TOP SECRET hardware posture not met: "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:2000` | `top secret` | `"TOP SECRET hardware gate waived by %s for: %s",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:2234` | `top secret` | `help="SECRET or TOP SECRET (TS mode defaults to TOP SECRET)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:2236` | `top secret` | `help="JSON dual-control receipt for TOP SECRET sends")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:2262` | `top secret` | `help="SECRET or TOP SECRET (TS mode defaults to TOP SECRET)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:2264` | `top secret` | `help="JSON dual-control receipt for TOP SECRET receives")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:2339` | `top secret` | `# TOP SECRET over public internet mandates the anonymity` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:2342` | `top secret` | `# TOP SECRET also mandates a hybrid-capable outer stack` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:2368` | `top secret` | `or "TOP SECRET"),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:2385` | `top secret` | `# TOP SECRET: no wildcard listener — bind the attested BLACK` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `secure_transmit_2027.py:2418` | `top secret` | `or "TOP SECRET"),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:5` | `maximum security` | `maximum security enforcement, and security manager initialization.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:9` | `maximum security` | `- Maximum security enforcement with no fallbacks` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:51` | `maximum security` | `- Maximum security enforcement` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:211` | `maximum security` | `"""Enforce maximum security requirements with no fallbacks."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:215` | `maximum security` | `self.log.info("Enforcing maximum security requirements...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:220` | `maximum security` | `# If we reach here, maximum security is achieved` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:221` | `maximum security` | `print("[OK] MAXIMUM SECURITY ACHIEVED")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:223` | `maximum security` | `# Update security hardening status to reflect maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:229` | `maximum security` | `self.log.info("Maximum security enforcement successful")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:236` | `maximum security` | `self.log.critical(f"Maximum security module not available: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:238` | `maximum security` | `"Maximum security enforcement not available",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:243` | `maximum security` | `self.log.critical(f"Maximum security enforcement failed: {e}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/hardening.py:245` | `maximum security` | `f"Maximum security enforcement failed: {e}",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security/monitor.py:175` | `maximum security` | `# Check every canary check interval for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_diagnostics.py:814` | `tactical` | `msg1 = b"Tactical Vector 001"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_diagnostics.py:821` | `tactical` | `msg2 = b"Tactical Ack 002"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_diagnostics.py:988` | `zero-trust` | `@check("f03", "FALLBACK", "Zero-Trust RBAC least-privilege & default-deny enforcement")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_diagnostics.py:1168` | `sovereign` | `" SOVEREIGN P2P // FULL-PROJECT SECURITY DIAGNOSTICS",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_diagnostics.py:1221` | `zero-trust` | `"  * Zero-Trust Authorization: Strict default-deny RBAC & constant-time validation",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:5` | `destroyer` | `Destroyer-ST2027 Comprehensive Multi-Tier Security Engine` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:10` | `tactical` | `2. BASIC: Standard tactical point-to-point link, field communications.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:12` | `mission-critical` | `4. HIGH: Mission-critical tactical mesh, DDIL, Noise_XXhfs + Double Ratchet,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:12` | `tactical` | `4. HIGH: Mission-critical tactical mesh, DDIL, Noise_XXhfs + Double Ratchet,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:14` | `sovereign` | `5. CRITICAL: Strategic sovereign release & nuclear command (NC3),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:14` | `nuclear command` | `5. CRITICAL: Strategic sovereign release & nuclear command (NC3),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:14` | `nuclear` | `5. CRITICAL: Strategic sovereign release & nuclear command (NC3),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:14` | `NC3` | `5. CRITICAL: Strategic sovereign release & nuclear command (NC3),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:139` | `tactical` | `description="Standard tactical point-to-point datalink with AES-256-GCM AEAD.",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:494` | `sovereign` | `"""Create an SP800_208_LMS stateful hash-based signer for CRITICAL tier sovereign release."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:559` | `sovereign` | `"""Create a dual-operator EmergencyPurgeCeremony for CRITICAL tier sovereign wipe."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:1625` | `sovereign` | `"""Sovereign Command & Control: Dual-Operator Emergency Anti-Tamper Purge Ceremony.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `security_tiers.py:1649` | `sovereign` | `"""Executes sovereign emergency purge across RAM and disk."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `sel4_baremetal/crypto_domain/src/main.rs:1` | `sovereign` | `//! Bare-Metal seL4 Microkit CRYPTO Protection Domain (Sovereign Core)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `sel4_microkit/system.xml:14` | `sovereign` | `<!-- 2. CRYPTO Protection Domain: Sovereign Cryptographic Engine & Key Storage -->` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `sovereign_black_domain.py:4` | `sovereign` | `seL4 BLACK Protection Domain for Sovereign Transmit 2027 (ST2027).` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_crypto_domain.py:4` | `sovereign` | `seL4 CRYPTO Protection Domain for Sovereign Transmit 2027 (ST2027).` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_crypto_domain.py:13` | `sovereign` | `- Sovereign: 256-bit NSA CSfC Pre-Shared Key (RFC 8784 compliance)` | (b) Standard Identifier | KEEP |
| `sovereign_crypto_domain.py:49` | `sovereign` | `"""Base error for sovereign crypto domain operations."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_crypto_domain.py:302` | `sovereign` | `# Sovereign CRYPTO Protection Domain Core` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_group_ratchet.py:2` | `sovereign` | `"""Sovereign Group Ratchet (CNSA Suite 2.0 / RFC 9420 MLS Aligned).` | (b) Standard Identifier | KEEP |
| `sovereign_group_ratchet.py:4` | `top secret` | `Provides Post-Quantum End-to-End Encrypted Group Messaging for Top Secret` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `sovereign_group_ratchet.py:5` | `sovereign` | `Sovereign Defense Enclaves.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_group_ratchet.py:27` | `sovereign` | `GROUP_PROTO_ID = b"ST2027-SOVEREIGN-GROUP-v1"` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_group_ratchet.py:84` | `sovereign` | `"""Sovereign Group Ratchet session manager."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_group_ratchet.py:234` | `NC3` | `raise ValueError("NC3 Two-Person Integrity violation: dual officer signatures required for epoch rekey")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `sovereign_group_ratchet.py:254` | `NC3` | `raise ValueError("NC3 Two-Person Integrity violation: invalid dual officer signatures for epoch rekey")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `sovereign_red_domain.py:4` | `sovereign` | `seL4 RED Protection Domain for Sovereign Transmit 2027 (ST2027).` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_red_domain.py:11` | `tactical` | `keypads, display sinks, or tactical audio interfaces.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `sovereign_sel4_appliance.py:3` | `sovereign` | `sovereign_sel4_appliance.py — Unified seL4 Sovereign Hardware Appliance Runtime` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_sel4_appliance.py:4` | `sovereign` | `for Sovereign Transmit 2027 (ST2027).` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_sel4_appliance.py:8` | `sovereign` | `- CRYPTO Domain: Sovereign PQC Triple-Hybrid engine with dual-rail verification` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_sel4_appliance.py:35` | `sovereign` | `"""An integrated seL4 Sovereign Appliance Node executing MILS separation."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `sovereign_sel4_appliance.py:71` | `sovereign` | `logger.info("Initialized seL4 Sovereign Appliance Node [%s] with MILS separation.", node_id)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `spo_dpo.py:3` | `top secret` | `spo_dpo.py — Single-Person vs Dual-Person Operation enforcement for TOP SECRET` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `spo_dpo.py:8` | `top secret` | `pre-transmit ceremony gate for secure_transmit_2027.py: no TOP SECRET blob` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `spo_dpo.py:15` | `top secret` | `below SECRET. Refused for TOP SECRET.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `spo_dpo.py:21` | `top secret` | `Mandatory for TOP SECRET. Always accepted where SPO would be accepted.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `spo_dpo.py:34` | `top secret` | `in TOP SECRET mode. A passphrase ceremony (critical_release.py) remains` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `spo_dpo.py:45` | `NC3` | `Temporal doctrine follows the NC3 dual-custody window already proven in` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `spo_dpo.py:110` | `top secret` | `# TOP SECRET demands dual control. Everything at SECRET and below accepts` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `spo_dpo.py:118` | `top secret` | `"TOP SECRET": MODE_DPO,` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `spo_dpo.py:706` | `top secret` | `# Deniable (AEAD-only, repudiable) sessions can never carry TOP SECRET /` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ssdf_attestation.py:197` | `sovereign` | `"product": "Secure P2P Sovereign Communications Engine v2.0.0-CNSA2-2027",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_cloaking_router.py:4` | `tactical` | `Tactical Network Cloaking & Overlay Routing Adapter for Contested Environments.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:6` | `tactical` | `Implements high-threat operational mode (P2P_TACTICAL_CLOAK=1 or --tactical-cloak):` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:7` | `tactical` | `- Enforces private tactical APN / WireGuard point-to-point overlay encapsulation.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:19` | `tactical` | `"""Raised when an operation violates tactical network cloaking policy."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:23` | `tactical` | `"""True when tactical cloaking is enforced via environment or command-line."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:30` | `tactical` | `"""Check if destination IP is private, loopback, link-local, or tactical overlay."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:48` | `tactical` | `Validate that an outbound network destination complies with tactical cloaking.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:49` | `tactical` | `Under tactical cloaking, unencapsulated direct public IP connections are blocked.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:54` | `tactical` | `# Under tactical cloaking, direct public sockets are forbidden unless overlay active` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:60` | `tactical` | `f"[TACTICAL CLOAK VIOLATION] Direct unencapsulated connection to public destination "` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:62` | `tactical` | `f"Route through tactical overlay, WireGuard point-to-point tunnel, or APN."` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:68` | `tactical` | `Validate that an inbound connection source complies with tactical cloaking.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:69` | `tactical` | `Under tactical cloaking, unencapsulated direct public IP connections are blocked.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:74` | `tactical` | `# Under tactical cloaking, direct public sockets are forbidden unless overlay active` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:80` | `tactical` | `f"[TACTICAL CLOAK VIOLATION] Direct unencapsulated connection from public source "` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:82` | `tactical` | `f"Incoming connections must arrive through tactical overlay, WireGuard point-to-point tunnel, or APN."` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:170` | `tactical` | `print("[*] Testing tactical cloaking router...")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:175` | `tactical` | `# Enable tactical cloak` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_cloaking_router.py:218` | `tactical` | `print("[PASS] Tactical cloaking router verified successfully.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_data_diode.py:3` | `tactical` | `Simplex Tactical Data Diode with Forward Error Correction (FEC)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_data_diode.py:7` | `tactical` | `- MIL-STD-188-220 & NATO STANAG 4586 (Tactical Data Telemetry)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_data_diode.py:22` | `tactical` | `3. Cursor-on-Target (CoT) Tactical Telemetry:` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_data_diode.py:23` | `tactical` | `- Native MIL-STD tactical telemetry framing for blue-force tracking and command status.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_data_diode.py:243` | `tactical` | `DIODE_MAGIC = b"TDD1"  # Tactical Data Diode v1 (4 bytes)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_data_diode.py:365` | `tactical` | `# 3. CURSOR-ON-TARGET (CoT) TACTICAL TELEMETRY` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_data_diode.py:372` | `tactical` | `Standard NATO STANAG / US DoD tactical awareness message.` | (b) Standard Identifier | KEEP |
| `tactical_data_diode.py:410` | `NC3` | `uid = f"NC3-COT-{uuid.uuid4().hex[:12].upper()}"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_key_provisioner.py:5` | `tactical` | `TACTICAL AIR-GAPPED KEY & PEER PROVISIONER (CNSA 2.0 / FIPS 140-3)` | (b) Standard Identifier | KEEP |
| `tactical_key_provisioner.py:8` | `sovereign` | `fingerprint whitelists for sovereign, zero-trust military P2P nodes.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_key_provisioner.py:8` | `zero-trust` | `fingerprint whitelists for sovereign, zero-trust military P2P nodes.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_key_provisioner.py:144` | `tactical` | `print(f"  [SECURITY] Generated ephemeral 256-bit tactical key passphrase for provisioning.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_key_provisioner.py:147` | `tactical` | `print(f"{BOLD}{CYAN}  PROVISIONING AIR-GAPPED TACTICAL CREDENTIALS (CNSA 2.0 / ML-DSA-87){RESET}")` | (b) Standard Identifier | KEEP |
| `tactical_key_provisioner.py:184` | `zero-trust` | `"description": "Authorized military peer certificate fingerprints for zero-trust P2P",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_key_provisioner.py:206` | `tactical` | `print(f"\n{BOLD}{GREEN}[SUCCESS] Tactical network provisioned in {output_dir}. Transfer out-of-band.{RESET}\n")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:5` | `tactical` | `Tactical Mesh Resilience for Disrupted, Disconnected, Intermittent, and Low-Bandwidth (DDIL) Environments.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:12` | `tactical` | `4. Adaptive packet pacing for low-bandwidth (< 64kbps) tactical military links.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:52` | `tactical` | `COMMAND = 1    # Tactical mission tasking` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:69` | `tactical` | `"""Pre-pinned Post-Quantum Keyring for Tactical DDIL Nodes (TETA Architecture)."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:81` | `tactical` | `"""Register a tactical node's public key and return its 32-byte Key ID."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:212` | `tactical` | `"refusing tactical bundle key derivation."` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:264` | `tactical` | `Tactical Identity Cache (TIC) per Tactical Edge Triad Architecture (TETA 2025/2026).` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:265` | `zero-trust` | `Caches identities, roles, and pre-attested credentials for zero-trust authorization offline.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_mesh_ddil.py:562` | `tactical` | `"(cryptography package missing); refusing to emit tactical bundles.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:629` | `tactical` | `The epoch root may be supplied explicitly or resolved from the tactical` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:643` | `tactical` | `"package missing); refusing to open tactical bundles.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:699` | `tactical` | `"""Tactical DDIL Mesh Router & Store-and-Forward Reconciler."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:706` | `tactical` | `# TETA Architecture: Tactical Identity Cache, Authority Decay, and Governance Envelopes` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:743` | `tactical` | `"""Update simulated or live link connectivity for a tactical peer."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:853` | `tactical` | `parser = argparse.ArgumentParser(description="DoD CSRMC Phase 5: Tactical DDIL Mesh Self-Test")` | (b) Standard Identifier | KEEP |
| `tactical_mesh_ddil.py:854` | `tactical` | `parser.add_argument("--test", action="store_true", help="Run tactical mesh self-test")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:858` | `tactical` | `print(" DoD CSRMC Phase 5: Tactical DDIL Mesh Resilience Self-Test")` | (b) Standard Identifier | KEEP |
| `tactical_mesh_ddil.py:861` | `tactical` | `# 1. Setup two tactical stations (Alpha and Bravo)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:870` | `tactical` | `# 3. Alpha queues 5 encrypted tactical bundles while offline with priority` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:957` | `tactical` | `print("[5/5] Testing Key-ID Compression for low-bandwidth tactical links...")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_mesh_ddil.py:977` | `tactical` | `print("\n[ALL 5/5 TACTICAL DDIL MESH TESTS PASSED SUCCESSFULLY]\n")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:4` | `destroyer` | `DESTROYER ST-2027: TACTICAL C4ISR OPERATIONS CONSOLE & MISSION STATION` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:4` | `tactical` | `DESTROYER ST-2027: TACTICAL C4ISR OPERATIONS CONSOLE & MISSION STATION` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:5` | `zero-trust` | `MILITARY SPECIFICATION: CNSA 2.0 / FIPS 203 / FIPS 204 / DoD Zero-Trust / NC3` | (b) Standard Identifier | KEEP |
| `tactical_operator_console.py:5` | `NC3` | `MILITARY SPECIFICATION: CNSA 2.0 / FIPS 203 / FIPS 204 / DoD Zero-Trust / NC3` | (b) Standard Identifier | KEEP |
| `tactical_operator_console.py:7` | `tactical` | `Turnkey operational tactical military station providing:` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:9` | `tactical` | `2. ATAK / WinTAK Tactical Tablet Integration Bridge (UDP 4242 / Multicast 239.2.3.1:6969).` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:10` | `tactical` | `3. Tactical Military Messaging (MMHS Precedence & Bell-LaPadula MLS / NSA RTB).` | (b) Standard Identifier | KEEP |
| `tactical_operator_console.py:11` | `tactical` | `4. Tactical Push-to-Talk (PTT) Voice Bursts with Flat Poisson Chaff Camouflage.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:12` | `nuclear` | `5. NC3 Nuclear & Strategic Command Two-Person Rule (Dual-Officer Custody).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:12` | `NC3` | `5. NC3 Nuclear & Strategic Command Two-Person Rule (Dual-Officer Custody).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:13` | `classified` | `6. Simplex Optical Data Diode Classified File Transfer (Air-gap / FEC).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:55` | `tactical` | `# ANSI Styling for Military Tactical Terminal` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:83` | `classified` | `# NSA RTB Classified Indicator / Dirty-Word Filter` | (b) Standard Identifier | KEEP |
| `tactical_operator_console.py:85` | `top secret` | `b"top secret",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:94` | `classified` | `"""Constant-time traversal checking for classified indicators."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:149` | `destroyer` | `return b"DESTROYER-ST2027-TACTICAL-MSG-v1\x00" + canonical_str.encode("utf-8")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:149` | `tactical` | `return b"DESTROYER-ST2027-TACTICAL-MSG-v1\x00" + canonical_str.encode("utf-8")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:153` | `NC3` | `"""Canonical NC3 domain-separated envelope binding EAM directive and dual officer credentials."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:155` | `NC3` | `return b"DESTROYER-ST2027-NC3-EAM\x00" + canonical_str.encode("utf-8")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:155` | `destroyer` | `return b"DESTROYER-ST2027-NC3-EAM\x00" + canonical_str.encode("utf-8")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:161` | `destroyer` | `return b"DESTROYER-ST2027-TACTICAL-PTT-v1\x00" + canonical_str.encode("utf-8")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:161` | `tactical` | `return b"DESTROYER-ST2027-TACTICAL-PTT-v1\x00" + canonical_str.encode("utf-8")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:166` | `tactical` | `Full-featured tactical military C4ISR communications station.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:223` | `tactical` | `"""Bind incoming tactical communications socket."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:232` | `tactical` | `"""Continuous background listener for incoming quantum tactical frames."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:268` | `tactical` | `"""Dissect, verify, and route incoming tactical datagrams."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:270` | `tactical` | `# Wire format: JSON tactical envelope: {"type": ..., "payload": ..., "sig": ..., "signer": ...}` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:347` | `tactical` | `# Forward to ATAK/WinTAK tactical tablets` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:360` | `tactical` | `print(f"\n{RED}[TACTICAL MSG DROPPED]{RESET} Stale or invalid timestamp from {signer}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:380` | `tactical` | `print(f"\n{RED}[TACTICAL MSG DROPPED]{RESET} Rejected unauthenticated or tampered message from {signer} (invalid ML-D...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:389` | `tactical` | `print(f"\n{RED}[TACTICAL MSG REPLAY DROPPED]{RESET} Duplicate signed message from {signer}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:395` | `tactical` | `print(f"\n{color}{BOLD}[TACTICAL RADIO RECV - {prec_name}]{RESET} From: {signer} \| Level: {clearance} // {caveats}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:401` | `tactical` | `"""Process push-to-talk tactical audio frame burst (A4-04 hardened).` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:441` | `tactical` | `print(f"\n{MAGENTA}[PTT VOICE RX]{RESET} Tactical voice burst from {BOLD}{signer}{RESET} ({chunks} frames, {duration_...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:458` | `NC3` | `print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REJECTED]{RESET} Single-custody attempt or missing officer identities f...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:463` | `NC3` | `print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REJECTED]{RESET} Stale or replayed EAM directive '{directive}' (timesta...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:478` | `NC3` | `print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REJECTED]{RESET} EAM directive '{directive}' REJECTED: signature verifi...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:489` | `NC3` | `print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REJECTED]{RESET} EAM directive '{directive}' REJECTED: custodian identi...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:497` | `NC3` | `print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REJECTED]{RESET} EAM directive '{directive}' REJECTED: missing/short an...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:505` | `NC3` | `print(f"\n{WHITE_ON_RED}[NC3 SECURITY ALERT - REPLAY REJECTED]{RESET} EAM directive '{directive}' REJECTED: nonce alr...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:510` | `NC3` | `print(f"\n{WHITE_ON_RED}[NC3 STRATEGIC EAM RECEIVED - DUAL AUTHENTICATED]{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:580` | `classified` | `"""Transmit priority-stamped, MLS-classified military message with canonical envelope authentication (TACT-03)."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:607` | `classified` | `print(f"{RED}[RTB SPILLAGE REJECTED]{RESET} Refusing outbound message containing classified indicator '{spill}' in {c...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:631` | `tactical` | `"""Simulate sending quantized tactical voice frames followed by Poisson chaff cover."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:683` | `NC3` | `print(f"{RED}[NC3 VIOLATION]{RESET} Two-Person Rule requires two distinct authorized officers!")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:699` | `NC3` | `print(f"{RED}[NC3 VIOLATION]{RESET} Second officer public key is required to bind the signature!")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:706` | `NC3` | `print(f"{RED}[NC3 VIOLATION]{RESET} Second officer public key is required to bind the signature!")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:710` | `NC3` | `print(f"{RED}[NC3 VIOLATION]{RESET} Two-Person Rule requires independently supplied second-officer credentials; refus...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:720` | `NC3` | `print(f"{RED}[NC3 VIOLATION]{RESET} Dual-custody signature verification failed!")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:728` | `NC3` | `print(f"{RED}[NC3 VIOLATION]{RESET} Both officers must be enrolled peers in production!")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:751` | `NC3` | `print(f"{WHITE_ON_RED}[NC3 STRATEGIC EAM AUTHORIZED & SENT]{RESET} Directive: {directive} [Officers: {officer1}, {off...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:793` | `tactical` | `print(f"\n{BOLD}{CYAN}--- TACTICAL SITREP: {self.node_name} [{self.callsign}] ---{RESET}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:801` | `zero-trust` | `print(f"  Zero-Trust Score   : {self.trust_score}/100 [ACD Shield Active]")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:805` | `tactical` | `print(f"\n{BOLD}{GREEN}=== BLUE FORCE TRACKING (BFT) / TACTICAL SITUATIONAL AWARENESS ==={RESET}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:819` | `tactical` | `Execute a full, two-base autonomous tactical battle drill:` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:825` | `tactical` | `print(f"{BOLD}{CYAN}  STARTING AUTONOMOUS TACTICAL C4ISR MILITARY MISSION DRILL                     {RESET}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:872` | `tactical` | `# 3. Tactical Push-to-Talk Voice Burst` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:873` | `tactical` | `print(f"\n{BOLD}[DRILL STEP 3/5] Transmitting Tactical PTT Encrypted Voice Burst...{RESET}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:877` | `NC3` | `# 4. Two-Person Rule NC3 EAM Authorization` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:878` | `NC3` | `print(f"\n{BOLD}[DRILL STEP 4/5] Two-Person Rule NC3 Strategic Action Message Dispatch...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:902` | `tactical` | `print(f"\n{BOLD}{BLACK_ON_GREEN}  AUTONOMOUS TACTICAL C4ISR DRILL COMPLETED WITH 100% SUCCESS  {RESET}\n")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:906` | `destroyer` | `parser = argparse.ArgumentParser(description="Destroyer ST-2027 Tactical C4ISR Station")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:906` | `tactical` | `parser = argparse.ArgumentParser(description="Destroyer ST-2027 Tactical C4ISR Station")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:907` | `tactical` | `parser.add_argument("--node", default="BASE-ALPHA", help="Tactical Node Name")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:908` | `tactical` | `parser.add_argument("--callsign", default="TACTICAL-01", help="Operator Callsign")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:909` | `tactical` | `parser.add_argument("--port", type=int, default=9050, help="Local tactical UDP port")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:918` | `tactical` | `parser.add_argument("--drill", action="store_true", help="Run automated 2-base tactical battle drill")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:919` | `sovereign` | `parser.add_argument("--sovereign", action="store_true", default=True, help="Launch sovereign tactical Zero-Gap node (...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:919` | `tactical` | `parser.add_argument("--sovereign", action="store_true", default=True, help="Launch sovereign tactical Zero-Gap node (...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:929` | `sovereign` | `# Default to the Sovereign Zero-Gap node (secure_p2p.py) with full post-quantum ratchet and 20ms pacing` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:932` | `sovereign` | `print(f"\n{BOLD}{CYAN}[SOVEREIGN HARDENING] Directing tactical console to Sovereign Zero-Gap P2P Engine (secure_p2p.p...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:932` | `tactical` | `print(f"\n{BOLD}{CYAN}[SOVEREIGN HARDENING] Directing tactical console to Sovereign Zero-Gap P2P Engine (secure_p2p.p...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:958` | `tactical` | `print(f"\n{BOLD}Type /help for tactical command list, or /drill for autonomous validation.{RESET}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:1001` | `tactical` | `print("  /sitrep                - View tactical station status")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:1005` | `tactical` | `print("  /ptt                   - Transmit tactical voice burst with chaff cover")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_operator_console.py:1006` | `NC3` | `print("  /eam                   - Dispatch NC3 Two-Person Rule EAM")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_operator_console.py:1007` | `tactical` | `print("  /drill                 - Run autonomous 2-base tactical mission drill")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/app.js:2` | `destroyer` | `DESTROYER TACTICAL P2P DEFCON-1 COMMAND CENTER (JAVASCRIPT LOGIC)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/app.js:2` | `tactical` | `DESTROYER TACTICAL P2P DEFCON-1 COMMAND CENTER (JAVASCRIPT LOGIC)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/app.js:273` | `NC3` | `appendChatMessage(sender, `[NC3/EAM-AUTH-DEFCON-1] ${directive} // DUAL-CUSTODIAN 2-OF-2 VERIFIED`);` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/app.js:284` | `NC3` | `appendChatMessage(peer, `[NC3 EAM RECEIPT CONFIRMED] SHA3: ${data.authenticator_sha3_512 ? data.authenticator_sha3_51...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/app.js:289` | `NC3` | `appendChatMessage(peer, `[NC3 EAM RECEIPT CONFIRMED] DUAL-CUSTODY AUTHENTICATED // TEMPORAL EXPIRY: 120s`);` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/app.js:466` | `top secret` | `if (!confirm('TOP SECRET ALERT: Are you certain you want to trigger NIST SP 800-88 3-Pass Emergency Media Sanitizatio...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/app.js:538` | `sovereign` | `setStep('DRILL COMPLETE: ALL 50X SOVEREIGN DEFENSE VECTORS SATISFIED! (10/10 GATES VERIFIED)');` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.css:2` | `destroyer` | `DESTROYER TACTICAL P2P DEFCON-1 COMMAND CENTER STYLESHEET (VANILLA CSS)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.css:2` | `tactical` | `DESTROYER TACTICAL P2P DEFCON-1 COMMAND CENTER STYLESHEET (VANILLA CSS)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.css:3` | `sovereign` | `Aesthetic: Sovereign Military HUD, Dark Enclave, Glassmorphism, Micro-Animations` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.css:1239` | `sovereign` | `.sovereign-table {` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.css:1247` | `sovereign` | `.sovereign-table th,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.css:1248` | `sovereign` | `.sovereign-table td {` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.css:1253` | `sovereign` | `.sovereign-table thead th {` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:7` | `sovereign` | `<meta name="description" content="Destroyer Tactical P2P: Sovereign Military Command Center with Post-Quantum NSA CNS...` | (b) Standard Identifier | KEEP |
| `tactical_web/index.html:7` | `destroyer` | `<meta name="description" content="Destroyer Tactical P2P: Sovereign Military Command Center with Post-Quantum NSA CNS...` | (b) Standard Identifier | KEEP |
| `tactical_web/index.html:7` | `tactical` | `<meta name="description" content="Destroyer Tactical P2P: Sovereign Military Command Center with Post-Quantum NSA CNS...` | (b) Standard Identifier | KEEP |
| `tactical_web/index.html:8` | `sovereign` | `<title>Destroyer Tactical P2P — Sovereign Defense Command Center</title>` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:8` | `destroyer` | `<title>Destroyer Tactical P2P — Sovereign Defense Command Center</title>` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:8` | `tactical` | `<title>Destroyer Tactical P2P — Sovereign Defense Command Center</title>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:16` | `sovereign` | `<span class="classification-text">TOP SECRET // CNSA SUITE 2.0 // NOFORN // SOVEREIGN MILITARY DATA PLANE</span>` | (b) Standard Identifier | KEEP |
| `tactical_web/index.html:16` | `top secret` | `<span class="classification-text">TOP SECRET // CNSA SUITE 2.0 // NOFORN // SOVEREIGN MILITARY DATA PLANE</span>` | (b) Standard Identifier | KEEP |
| `tactical_web/index.html:29` | `destroyer` | `<h1 id="app-title">DESTROYER TACTICAL P2P COMMAND CENTER</h1>` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:29` | `tactical` | `<h1 id="app-title">DESTROYER TACTICAL P2P COMMAND CENTER</h1>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:30` | `sovereign` | `<p class="subtitle">Sovereign Military Communications System &bull; Post-Quantum Enclave</p>` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:55` | `tactical` | `<button class="nav-tab active" id="tab-overview" role="tab" aria-selected="true" aria-controls="view-overview" onclic...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:56` | `classified` | `<button class="nav-tab" id="tab-comms" role="tab" aria-selected="false" aria-controls="view-comms" onclick="switchTab...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:59` | `sovereign` | `<button class="nav-tab" id="tab-sovereignty" role="tab" aria-selected="false" aria-controls="view-sovereignty" onclic...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:73` | `tactical` | `<span id="drill-status-text">INITIATING TACTICAL P2P DRILL...</span>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:81` | `tactical` | `<!-- VIEW 1: OVERVIEW & TACTICAL LINK -->` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:88` | `sovereign` | `<h2>SOVEREIGN DUAL-TERMINAL TOPOLOGY</h2>` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:211` | `tactical` | `<span>TACTICAL DATA PLANE COUNTERS</span>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:238` | `classified` | `<!-- VIEW 2: IN-BAND CLASSIFIED COMMS -->` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:245` | `classified` | `<h2>CLASSIFIED IN-BAND TACTICAL STREAM</h2>` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:245` | `tactical` | `<h2>CLASSIFIED IN-BAND TACTICAL STREAM</h2>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:259` | `tactical` | `<span class="msg-text">TACTICAL SECURE CHANNEL ARMED. 20ms Continuous Hardware Pacing Active.</span>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:272` | `tactical` | `<button class="preset-btn" onclick="sendPreset('TACTICAL ORDER: COMMENCE ALLIED AIR PATROL PATTERN-B')">TACTICAL ORDE...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:273` | `nuclear` | `<button class="preset-btn" style="border-color: #ff0055; color: #ff0055;" onclick="triggerEAMDirective()">NC3 NUCLEAR...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:273` | `NC3` | `<button class="preset-btn" style="border-color: #ff0055; color: #ff0055;" onclick="triggerEAMDirective()">NC3 NUCLEAR...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:279` | `tactical` | `<label for="msg-input" class="sr-only">Encrypted Tactical Message</label>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:280` | `classified` | `<input type="text" id="msg-input" class="chat-input" placeholder="Type classified tactical message (embedded in 20ms ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:280` | `tactical` | `<input type="text" id="msg-input" class="chat-input" placeholder="Type classified tactical message (embedded in 20ms ...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:292` | `tactical` | `<span class="badge badge-yellow">TACTICAL SITUATIONAL AWARENESS</span>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:296` | `tactical` | `Broadcast authenticated situational awareness tracks. Each event is signed with ML-DSA-87 and encoded for tactical li...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:339` | `tactical` | `<div class="cot-tracks-header">RECENT TACTICAL TRACKS</div>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:456` | `tactical` | `<label for="diode-file-name">TACTICAL PAYLOAD / FILE NAME</label>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:521` | `sovereign` | `<!-- VIEW 5: 50X SOVEREIGN MATRIX -->` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:525` | `sovereign` | `<h2>SOVEREIGN DEFENSE SUPERIORITY: ST2027 VS CONSUMER MESSAGING</h2>` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:530` | `destroyer` | `Empirical comparative analysis proving why Destroyer Tactical P2P is superior to commercial consumer messaging apps (...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:530` | `tactical` | `Empirical comparative analysis proving why Destroyer Tactical P2P is superior to commercial consumer messaging apps (...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:534` | `sovereign` | `<table class="sovereign-table" id="sovereign-matrix-table">` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:538` | `destroyer` | `<th scope="col" class="highlight-col">DESTROYER TACTICAL P2P</th>` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:538` | `tactical` | `<th scope="col" class="highlight-col">DESTROYER TACTICAL P2P</th>` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web/index.html:670` | `sovereign` | `<span>SOVEREIGN TRANSMIT 2027 (ST2027)</span> &bull;` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web/index.html:676` | `top secret` | `<span>CLASSIFICATION: TOP SECRET // NOFORN</span>` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web_console.py:8` | `NC3` | `a hardware-certified optical diode, and NOT an operational NC3 launch console.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web_console.py:102` | `top secret` | `EAM_CLASSIFICATION = "TOP SECRET//NOFORN"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web_console.py:122` | `tactical` | `"""Custom HTTP handler serving tactical web assets and REST APIs."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web_console.py:651` | `tactical` | `"""Launch the DEFCON-1 Tactical Web Command Center."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web_console.py:653` | `tactical` | `raise FileNotFoundError(f"Tactical web directory not found at {WEB_DIR}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web_console.py:658` | `tactical` | `print(f"  [DEFCON-1 TACTICAL P2P WEB COMMAND CENTER ONLINE]")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tactical_web_console.py:661` | `sovereign` | `print(f"  ZERO-TRUST : 100% Air-Gapped, No Cloud Relays, Pure Sovereign P2P")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web_console.py:661` | `zero-trust` | `print(f"  ZERO-TRUST : 100% Air-Gapped, No Cloud Relays, Pure Sovereign P2P")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tactical_web_console.py:673` | `tactical` | `print("\n[Tactical Web Server Shutting Down]")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `test-results/TEST_AND_BUILD_REPORT.md:78` | `NC3` | `[TEST STEP 5] NC3 strict keyword safety gate enforcement passed.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal.py:12` | `classified` | `- Classified bidirectional flash order exchange` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal.py:43` | `top secret` | `"CLASSIFIED // TOP SECRET // CNSA 2.0 // NOFORN\n"` | (b) Standard Identifier | KEEP |
| `test_real_uses_dual_terminal.py:43` | `classified` | `"CLASSIFIED // TOP SECRET // CNSA 2.0 // NOFORN\n"` | (b) Standard Identifier | KEEP |
| `test_real_uses_dual_terminal.py:130` | `tactical` | `assert wait_for(alpha_lines, "TACTICAL SECURE CHANNEL ESTABLISHED", timeout=25, desc="Alpha Channel Ready"), "Alpha f...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal.py:131` | `tactical` | `assert wait_for(bravo_lines, "TACTICAL SECURE CHANNEL ESTABLISHED", timeout=25, desc="Bravo Channel Ready"), "Bravo f...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal.py:149` | `classified` | `# STEP 3: Real Use Case 1 - Send Classified Tactical Message from Bravo to Alpha` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal.py:149` | `tactical` | `# STEP 3: Real Use Case 1 - Send Classified Tactical Message from Bravo to Alpha` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal.py:150` | `classified` | `print(f"\n{BOLD}[TEST STEP 3] Real Use Case 1: Classified Message from Bravo to Alpha...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal.py:183` | `tactical` | `print(f"\n{BOLD}[TEST STEP 8] Real Use Case 6: In-Band Tactical Document Streaming...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal.py:196` | `tactical` | `assert wait_for(alpha_lines, "TACTICAL NODE STATUS", timeout=10, desc="Status banner"), "Status banner missing"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal_ipv6.py:13` | `classified` | `- Classified bidirectional flash order exchange over IPv6` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal_ipv6.py:42` | `top secret` | `"CLASSIFIED // TOP SECRET // CNSA 2.0 // NOFORN\n"` | (b) Standard Identifier | KEEP |
| `test_real_uses_dual_terminal_ipv6.py:42` | `classified` | `"CLASSIFIED // TOP SECRET // CNSA 2.0 // NOFORN\n"` | (b) Standard Identifier | KEEP |
| `test_real_uses_dual_terminal_ipv6.py:121` | `tactical` | `assert wait_for(alpha_lines, "TACTICAL SECURE CHANNEL ESTABLISHED", timeout=30, desc="Alpha Channel Established"), "A...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal_ipv6.py:122` | `tactical` | `assert wait_for(bravo_lines, "TACTICAL SECURE CHANNEL ESTABLISHED", timeout=30, desc="Bravo Channel Established"), "B...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `test_real_uses_dual_terminal_ipv6.py:141` | `classified` | `print(f"\n{BOLD}[TEST STEP 3] Real Use Case 1: Classified Message from Bravo to Alpha over IPv6...{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/conftest.py:12` | `NC3` | `subsystems, incl. NC3 officer storage, off disk). Tests that construct an` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/conftest.py:14` | `NC3` | `tests onto the in-memory path (nc3 sealed-credential roundtrip never` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2027_defense_hardening.py:3` | `sovereign` | `2027+ Defense-Grade Sovereign Security Hardening Verification Suite` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2027_defense_hardening.py:8` | `sovereign` | `3. Sovereign Cloud Lockdown: Prohibition of Public Cloud OAuth2 in Production` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2027_defense_hardening.py:23` | `destroyer` | `PROJECT_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Pa...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2027_defense_hardening.py:244` | `sovereign` | `# 3. Sovereign OAuth2 Lockdown Tests` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2027_defense_hardening.py:256` | `sovereign` | `self.assertIn("prohibited in sovereign production mode", str(ctx.exception))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2027_defense_hardening.py:477` | `classified` | `The report is SELF-ASSESSMENT (not independent, not classified, no` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2028_national_security_remediations.py:5` | `zero-trust` | `1. Zero-Trust RBAC & Fine-Grained Authorization` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2028_national_security_remediations.py:56` | `zero-trust` | `"""Test 1: Zero-Trust Role-Based Access Control and Granular Authorization."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2028_national_security_remediations.py:62` | `NC3` | `"""Operators can send chat and files, but never NC3 or emergency release."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2028_national_security_remediations.py:77` | `NC3` | `"""Commanders hold NC3 launch and emergency release authorization."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2028_national_security_remediations.py:455` | `NC3` | `"""Test 9: Real Hardware Probing, Non-Silent Fallback Warnings, and NC3 Key Isolation."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_2028_national_security_remediations.py:497` | `NC3` | `"""NC3 OfficerIdentity rejects secret key dictionary serialization in production mode."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_anonymous_loopback.py:27` | `top secret` | `ch = ceremony.issue_challenge("op-anon-loop", "TOP SECRET", data)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_anonymous_loopback.py:43` | `top secret` | `classification="TOP SECRET", receipt=receipt)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_anonymous_loopback.py:55` | `top secret` | `classification="TOP SECRET", receipt=receipt,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit4_remediations_2026_10_17.py:25` | `NC3` | `A4-24 NC3 live-transfer test war key de-hardcoding` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit4_remediations_2026_10_17.py:415` | `destroyer` | `import destroyer` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_audit4_remediations_2026_10_17.py:419` | `destroyer` | `key_path, _state = destroyer._provision_diode_key_material()` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit4_remediations_2026_10_17.py:424` | `destroyer` | `key_path2, _ = destroyer._provision_diode_key_material()` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit4_remediations_2026_10_17.py:428` | `destroyer` | `key_path3, _ = destroyer._provision_diode_key_material()` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit_confirmed_regressions.py:402` | `top secret` | `metadata={"classification": "TOP SECRET"}` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit_confirmed_regressions.py:411` | `top secret` | `self.assertNotIn(b"TOP SECRET", env_bytes)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit_confirmed_regressions.py:418` | `top secret` | `self.assertEqual(restored_eph.metadata.get("classification"), "TOP SECRET")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit_forensic_remediations.py:7` | `tactical` | `- TACT-03: Tactical message metadata (precedence, clearance, caveats) authenticated in envelope.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit_forensic_remediations.py:9` | `tactical` | `- Bandit B104: Configurable localhost bind host in tactical console network listener.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit_forensic_remediations.py:322` | `tactical` | `"""SEC-08: _production() in decentralized & tactical architectures fails closed."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_audit_forensic_remediations.py:386` | `top secret` | `payload = b"Top secret operational command"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_cli_key_fill_and_diode.py:56` | `tactical` | `"kind": "tactical-war-order-keys",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_cli_key_fill_and_diode.py:84` | `NC3` | `# End-to-end: the NC3 war-key path must USE the imported key` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_cnsa_max_profile.py:3` | `sovereign` | `Test Suite for 2026 CNSA 2.0 Sovereign Max Cryptographic Profile` | (b) Standard Identifier | KEEP |
| `tests/test_cnsa_max_profile.py:190` | `sovereign` | `print("  CNSA 2.0 SOVEREIGN MAX CRYPTOGRAPHIC PROFILE VERIFICATION BATTERY")` | (b) Standard Identifier | KEEP |
| `tests/test_cnsa_max_profile.py:198` | `sovereign` | `print("  [SUCCESS] ALL CNSA 2.0 SOVEREIGN MAX PROFILE TESTS PASSED 100%!")` | (b) Standard Identifier | KEEP |
| `tests/test_cp1252_encoding_safety.py:63` | `sovereign` | `fb.show_success("Handshake established with sovereign PKI")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_defensive_audit_remediations.py:5` | `tactical` | `1. Tactical key provisioner fail-closed (no hardcoded password, PBKDF2-210k).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_defensive_audit_remediations.py:47` | `tactical` | `"""Verify tactical key provisioner strictly fails closed without credentials and uses 210k iterations."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_defensive_audit_remediations.py:61` | `tactical` | `test_pw = "Tactical-Defense-Passphrase-2026-NIST-Level5"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_defensive_nc3_audit.py:3` | `NC3` | `Zero-Gap Defensive Security Audit Suite for Direct-P2P Military Messaging (NC3/EAM)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_defensive_nc3_audit.py:43` | `NC3` | `os.environ["P2P_OFFICER_SEAL_PW"] = "test-seal-passphrase-nc3-audit"` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_defensive_nc3_audit.py:44` | `NC3` | `cls.nc3 = NC3CommandController()` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_defensive_nc3_audit.py:66` | `NC3` | `eam = self.nc3.create_nuclear_eam(` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_defensive_nc3_audit.py:79` | `NC3` | `self.nc3.verify_and_decrypt_nuclear_eam(` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_defensive_nc3_audit.py:92` | `NC3` | `self.nc3.verify_and_decrypt_nuclear_eam(` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_defensive_nc3_audit.py:105` | `NC3` | `self.nc3.verify_and_decrypt_nuclear_eam(` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_defensive_nc3_audit.py:117` | `NC3` | `decrypted = self.nc3.verify_and_decrypt_nuclear_eam(` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_defensive_nc3_audit.py:178` | `NC3` | `print("\n[PASS] P0.3: NC3 wire payloads uniformly padded to exact 1024B blocks.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_defensive_nc3_audit.py:199` | `zero-trust` | `self.assertIn("persistence prohibited under military zero-trust policy", str(ctx.exception))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_defensive_nc3_audit.py:202` | `zero-trust` | `print("\n[PASS] P0.5: Enclave KEK seed persistence prohibited in strict zero-trust mode.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_destroyer_core_production.py:143` | `top secret` | `q, frame = a.seal_msg(0x01, list(b"Top Secret Message"))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_destroyer_core_production.py:226` | `destroyer` | `salt=b"destroyer-p2p-rust-v1",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_destroyer_core_production.py:227` | `destroyer` | `info=b"destroyer/frame/v1",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_destroyer_core_production.py:235` | `destroyer` | `salt=b"destroyer-p2p-rust-v1",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_destroyer_core_production.py:236` | `destroyer` | `info=b"destroyer/frame/v1",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_docs_truth_in_claims.py:22` | `destroyer` | `ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__fil...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_exploit_nonce_state.py:28` | `destroyer` | `ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__fil...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_exploit_regressions.py:35` | `destroyer` | `ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / "destroyer.py").exists() else Path(__fil...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_exploit_regressions.py:111` | `destroyer` | `ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__fil...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_f06_symlink_atomic_write.py:15` | `top secret` | `data = b"TOP SECRET MISSION PAYLOAD 2027"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_f08_f09_tactical_and_inner_ratchet.py:31` | `top secret` | `"classification": "TOP SECRET",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_f10_fips_reporting.py:1` | `destroyer` | `"""Regression test for F-10: Accurate FIPS 140-3 and CMVP status reporting in destroyer.py."""` | (b) Standard Identifier | KEEP |
| `tests/test_f10_fips_reporting.py:5` | `destroyer` | `from destroyer import probe_hardware_and_environment` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_formal_proverif_models.py:81` | `NC3` | `# Check essential DoD NC3 queries` | (b) Standard Identifier | KEEP |
| `tests/test_fullreview_critical_remediations.py:8` | `NC3` | `C5     secure_p2p: NC3 war key fails closed (no public-constant fallback)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_fullreview_critical_remediations.py:155` | `NC3` | `# C5: NC3 war key fail-closed` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_fullreview_critical_remediations.py:383` | `sovereign` | `# C11: sovereign group ratchet TPI (supplemental to dedicated test file)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_fullreview_critical_remediations.py:831` | `NC3` | `# HIGH NC3-console cluster (2026-10 full-review triage)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_fullreview_critical_remediations.py:911` | `NC3` | `import nc3_nuclear_command as nc3` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_fullreview_critical_remediations.py:939` | `NC3` | `nc3, "load_officer_public_key", lambda _cid: wrong` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_fullreview_critical_remediations.py:1172` | `destroyer` | `# HIGH destroyer modules cluster (2026-10 full-review triage)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_fullreview_critical_remediations.py:1174` | `NC3` | `#   X-h2 NC3 EAM on the paced path must not assert two-person verification` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_fullreview_critical_remediations.py:1317` | `sovereign` | `#   F-h2 sovereign group ratchet: verify-before-commit` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_group_tier3.py:201` | `top secret` | `mgr.set_clearance("g", "alice", "TOP SECRET", ("SIERRA", "FOXTROT"))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_group_tier3.py:207` | `top secret` | `mgr.set_clearance("g", "alice", "TOP SECRET", ("SIERRA", "FOXTROT"))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_group_tier3.py:209` | `top secret` | `top = mgr.seal_labeled("g", b"eyes-only", "TOP SECRET", ("SIERRA",))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_group_tier3.py:225` | `top secret` | `mgr.set_clearance("g", "alice", "TOP SECRET", ("SIERRA",))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_group_tier3.py:226` | `top secret` | `sealed = mgr.seal_labeled("g", b"data", "TOP SECRET", ("SIERRA",))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_legacy_quarantine.py:37` | `sovereign` | `"""secure_p2p.py arms sovereign military mode when P2P_TS_MODE is set."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_legacy_quarantine.py:51` | `sovereign` | `"""secure_p2p.py arms production sovereign mode when P2P_PRODUCTION is set."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_legacy_quarantine.py:64` | `sovereign` | `"""Verify secure_p2p.py is present at repository root as the front sovereign application.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:14` | `classified` | `[TRIAL 4] Top-Secret Classified File Transfer (128KB SHA3-512 Bitwise Verification)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:246` | `tactical` | `print("and re-transmits (replays) it to trigger duplicate execution of tactical orders.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:284` | `classified` | `# TRIAL 4: TOP-SECRET CLASSIFIED FILE TRANSFER WITH SHA3-512 INTEGRITY & SHREDDING` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:287` | `classified` | `print_banner("[TRIAL 4] TOP-SECRET CLASSIFIED FILE TRANSFER (128KB SHA3-512 VERIFIED)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:288` | `classified` | `print("Scenario: Transmitting classified military satellite telemetry data file (128 KB)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:292` | `classified` | `# Create realistic 128KB classified satellite telemetry dataset` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:294` | `top secret` | `header = b"CLASSIFICATION: TOP SECRET // CNSA 2.0 // NOFORN\nORBITAL_VECTOR_TELEMETRY_STREAM_2026\n"` | (b) Standard Identifier | KEEP |
| `tests/test_military_adversarial_suite.py:374` | `tactical` | `print("Scenario: Exchanging successive tactical commands, ratcheting keys forward,")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:390` | `tactical` | `b"TACTICAL OBJECTIVE COMPLETE"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:526` | `tactical` | `print(f"  {GREEN}[PASS] Base Alpha (NORAD) & Base Bravo (Pentagon) completed full tactical mission drill!{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:537` | `tactical` | `TACTICAL DEFENSE NETWORK // ADVERSARIAL VERIFICATION & PENETRATION SUITE` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:538` | `zero-trust` | `STANDARDS: CNSA 2.0 / FIPS 140-3 LEVEL 3 / ZERO-TRUST HIGH-ASSURANCE BASELINE` | (b) Standard Identifier | KEEP |
| `tests/test_military_adversarial_suite.py:545` | `classified` | `("TRIAL 4: Top-Secret Classified File Transfer (128KB SHA3-512)", trial_4_classified_file_transfer),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_adversarial_suite.py:549` | `tactical` | `("TRIAL 8: Live Dual-Base Tactical Drill (NORAD vs. Pentagon)", trial_8_live_dual_base_drill),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_bases_two_terminal_live_drill.py:5` | `tactical` | `Validates end-to-end tactical operations between Base Alpha (NORAD Strategic Defense Command)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_five_pillars_operational.py:5` | `sovereign` | `End-to-end verification of the 5 Sovereign Military Tactical Pillars:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_five_pillars_operational.py:5` | `tactical` | `End-to-end verification of the 5 Sovereign Military Tactical Pillars:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_five_pillars_operational.py:35` | `tactical` | `self.psk_path = os.path.join(self.tmp_dir, "tactical.psk")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_military_five_pillars_operational.py:147` | `zero-trust` | `"""Pillar 4: TPM 2.0 PCR attestation and dynamic zero-trust continuous verification."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_nc3_cnsa_cipher.py:2` | `NC3` | `"""NC3 PAL bulk cipher: AES-256-GCM seals, legacy ChaCha verifies, tamper fails."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_cnsa_cipher.py:74` | `NC3` | `# of the PAL cipher again. Seal path lives in nc3 (_pal_encrypt,` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:3` | `nuclear command` | `NC3 (Nuclear Command, Control, and Communications) Verification Battery` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_nc3_nuclear_command_readiness.py:3` | `nuclear` | `NC3 (Nuclear Command, Control, and Communications) Verification Battery` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:3` | `NC3` | `NC3 (Nuclear Command, Control, and Communications) Verification Battery` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:5` | `nuclear` | `Validates that the system is ready for Nuclear-Grade Command and Control,` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:10` | `NC3` | `- CJCSI 3265.01 (NC3 Security Baseline)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:22` | `destroyer` | `PROJECT_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Pa...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_nc3_nuclear_command_readiness.py:69` | `sovereign` | `print("    [OK] Strategic Officers Provisioned with Sovereign ML-DSA-87 Keys.")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_nc3_nuclear_command_readiness.py:89` | `top secret` | `self.assertEqual(eam.classification, "TOP SECRET // SI-OP-IA // NC3 // NOFORN")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_nc3_nuclear_command_readiness.py:89` | `NC3` | `self.assertEqual(eam.classification, "TOP SECRET // SI-OP-IA // NC3 // NOFORN")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:104` | `NC3` | `print(f"\n  [NC3 TRIAL 1] Two-Person Rule Verified: Dual-Officer EAM successfully authenticated and unsealed.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:118` | `NC3` | `print("  [NC3 TRIAL 2] Single-Officer Impersonation Blocked (DualCustodyViolation).")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:161` | `NC3` | `print("  [NC3 TRIAL 3] Tampered EAM Payload Rejected Fail-Closed (100% Tamper Proof).")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:189` | `NC3` | `print("  [NC3 TRIAL 4] Stale EAM Rejected Upon Window Expiration (EAMExpiredError).")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:226` | `NC3` | `print("  [NC3 TRIAL 5] EAM Replay Attack Neutralized (EAMReplayError).")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:230` | `classified` | `sensitive_code = bytearray(b"PAL-CLASSIFIED-TOP-SECRET-CODE-88992211")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_nc3_nuclear_command_readiness.py:241` | `NC3` | `print(f"  [NC3 TRIAL 6] DoD 5220.22-M 3-Pass Memory Sanitization Confirmed (All {length} bytes wiped).")` | (b) Standard Identifier | KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:245` | `nuclear` | `Verify end-to-end nuclear EAM transmission through the destroyer_core Rust data plane.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:253` | `nuclear` | `pal_code = "NUCLEAR-AUTHENTICATOR-CODE-ZULU-999"` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:293` | `nuclear` | `print("  [NC3 TRIAL 7] Nuclear EAM Successfully Transmitted Over Rust Data Plane Double Envelope.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:293` | `NC3` | `print("  [NC3 TRIAL 7] Nuclear EAM Successfully Transmitted Over Rust Data Plane Double Envelope.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:333` | `NC3` | `print("  [NC3 TRIAL 8] Default War-Order Key Prohibited Fail-Closed.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_nuclear_command_readiness.py:369` | `NC3` | `print("  [NC3 TRIAL 9] Sealed Officer Credentials Verified (AES-256-GCM at rest).")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_person_integrity.py:3` | `NC3` | `Test Suite: NC3 / PAL Two-Person Integrity (TPI) & Dual-Custody Hardware Protocol` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_person_integrity.py:9` | `sovereign` | `2. Hardware Challenge-Response: Sovereign ML-DSA-87 signatures, unique physical token enforcement.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_nc3_two_person_integrity.py:286` | `NC3` | `# 4. END-TO-END NC3 EAM WITH VSS AND DUAL HARDWARE TOKENS` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_person_integrity.py:315` | `nuclear` | `# 3. Create Nuclear EAM using VSS shares and hardware responses` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_nc3_two_terminal_live_transfer.py:3` | `NC3` | `NC3 TWO-TERMINAL LIVE INTEGRATION TEST (SECURE_P2.PY)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:7` | `NC3` | `executes /nc3-send under Two-Person Rule, receives EAM, authenticates and unseals PAL code` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:8` | `NC3` | `with /nc3-verify under Dual-Custody, tests /zeroize, and validates 100% operational readiness.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:50` | `NC3` | `print_banner("NC3 TWO-TERMINAL LIVE EAM TRANSFER & VERIFICATION TEST")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:52` | `NC3` | `print("Testing: Two-Person Rule /nc3-send, EAM reception alert, /nc3-verify unsealing, and /zeroize.")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:71` | `NC3` | `P2P_OFFICER_SEAL_PW="nc3-live-transfer-test-seal-only",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:323` | `nuclear` | `# 4. Dispatch Nuclear EAM from NORAD (Station Alpha)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_nc3_two_terminal_live_transfer.py:325` | `NC3` | `eam_command = "/nc3-send FLASH-DEFCON1-STRIKE-PLAN TARGET-VECTOR-OMNI 9941-8823-ALPHA-ZULU-7711\n"` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:326` | `NC3` | `print(f"[ORCHESTRATOR] Dispatching NC3 EAM from NORAD: {eam_command.strip()}")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:331` | `NC3` | `raise RuntimeError("Station Alpha failed to broadcast NC3 Emergency Action Message!")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:336` | `NC3` | `raise RuntimeError("Station Bravo did not detect incoming NC3 EAM alert!")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:341` | `NC3` | `verify_command = "/nc3-verify COL_CHARLIE CAPT_DELTA\n"` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:380` | `NC3` | `print("  [ALL NC3 TWO-TERMINAL LIVE VERIFICATION CHECKS PASSED 100%]")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:386` | `NC3` | `"""Pytest gate: full NC3 two-terminal live run (Two-Person Rule` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_nc3_two_terminal_live_transfer.py:387` | `NC3` | `/nc3-send, EAM alert, dual-officer /nc3-verify unseal, /zeroize).` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_network_endpoint_discovery.py:12` | `tactical` | `6. Tactical cloak / air-gapped zero-egress policy enforcement.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_network_endpoint_discovery.py:111` | `tactical` | `"""In air-gap or tactical cloak mode, STUN queries must be completely bypassed."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_emoji_property.py:22` | `destroyer` | `PROJECT_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / "destroyer.py").exists() else Pa...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:5` | `sovereign` | `ZERO-GAP SOVEREIGN MILITARY AUDIT & PENETRATION BATTERY` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:49` | `zero-trust` | `# TRIAL 1: ZERO-TRUST WHITELIST ENFORCEMENT & ROGUE PEER REJECTION` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:52` | `zero-trust` | `print_stage(1, "ZERO-TRUST PRE-SHARED WHITELIST ENFORCEMENT", "Active Nation-State In-Path Attacker Attempts In-Band ...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:90` | `zero-trust` | `print(f"  {GREEN}[PASS] Pre-authorized Base Alpha certificate accepted by zero-trust whitelist.{RESET}")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:99` | `classified` | `print("Testing uniform block padding across micro, medium, and large classified payloads...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:146` | `tactical` | `# Send a sequence alternating between cover chaff and real tactical messages` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:254` | `tactical` | `print_stage(5, "OUT-OF-BAND TACTICAL CREDENTIAL VALIDATION", "Deployment over Untrusted Public Internet with Zero In-...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:255` | `tactical` | `print("Verifying tactical manifest and pre-shared certificates generated by provisioner...")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:300` | `sovereign` | `ZERO-GAP SOVEREIGN MILITARY AUDIT & PENETRATION SUITE` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:301` | `zero-trust` | `STANDARDS: ZERO-TRUST WHITELIST / UNIFORM FRAMING / CHAFF TRAFFIC / STEALTH` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:305` | `zero-trust` | `("TRIAL 1: Zero-Trust Pre-Shared Whitelist Enforcement", test_zero_trust_whitelist),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:309` | `tactical` | `("TRIAL 5: Out-of-Band Tactical Credential Validation", test_tactical_pre_shared_manifest),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_gap_military_audit.py:337` | `zero-trust` | `• IN-BAND MITM: Neutralized via Pre-Shared Zero-Trust Fingerprint Whitelisting` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:11` | `military-grade` | `"BEYOND MILITARY-GRADE", "QUANTUM SUPREME", "REVOLUTIONARY", "CUTTING-EDGE",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:11` | `cutting-edge` | `"BEYOND MILITARY-GRADE", "QUANTUM SUPREME", "REVOLUTIONARY", "CUTTING-EDGE",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:11` | `revolutionary` | `"BEYOND MILITARY-GRADE", "QUANTUM SUPREME", "REVOLUTIONARY", "CUTTING-EDGE",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:12` | `world-class` | `"GAME-CHANGING", "WORLD-CLASS".` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:23` | `destroyer` | `PROJECT_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / "destroyer.py").exists() else Pa...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:140` | `cutting-edge` | `test_text = "This is an ULTIMATE solution with CUTTING-EDGE technology."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:146` | `cutting-edge` | `assert "CUTTING-EDGE" in buzzword_strings  # nosec: B101` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:150` | `cutting-edge` | `test_text = "This ULTIMATE system provides CUTTING-EDGE security."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:155` | `cutting-edge` | `assert "CUTTING-EDGE" not in cleaned_text  # nosec: B101` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:163` | `military-grade` | `"BEYOND MILITARY-GRADE protection",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:165` | `revolutionary` | `"REVOLUTIONARY technology",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:166` | `cutting-edge` | `"CUTTING-EDGE features",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:168` | `world-class` | `"WORLD-CLASS implementation"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:181` | `cutting-edge` | `"cutting-edge features",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:182` | `cutting-edge` | `"Cutting-Edge Features",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_no_marketing_buzzwords_property.py:183` | `cutting-edge` | `"CUTTING-EDGE FEATURES"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_noise_pq_hardened.py:4` | `sovereign` | `Sovereign Defense Hardening Test Suite:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:6` | `sovereign` | `2. Sovereign production mode gate blocking external OAuth validation.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:50` | `sovereign` | `# In sovereign production mode, instantiating public OAuth throws AuthenticationError` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:58` | `destroyer` | `"email": "pilot@destroyer.mil",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:60` | `tactical` | `"name": "Tactical Pilot"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:66` | `destroyer` | `assert identity == "pilot@destroyer.mil"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:72` | `tactical` | `"userPrincipalName": "commander@cosp-tactical.org",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:74` | `tactical` | `"mail": "commander@cosp-tactical.org"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:80` | `tactical` | `assert identity == "commander@cosp-tactical.org"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:86` | `destroyer` | `"login": "destroyer-agent",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:87` | `destroyer` | `"name": "Destroyer Core Agent"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:93` | `destroyer` | `assert identity == "destroyer-agent"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:151` | `destroyer` | `mock_user = {"email": "verified@destroyer.mil"}` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:152` | `destroyer` | `with patch.object(mgr.oauth_auth, 'validate_received_token', return_value=(True, mock_user, "verified@destroyer.mil")):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_oauth_token_validation_p0.py:156` | `destroyer` | `assert mgr.authenticated_user == "verified@destroyer.mil"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_pbkdf2_migration_and_group_architecture.py:117` | `tactical` | `secret_payload = b"-----BEGIN TACTICAL SECRET KEY-----\nSAMPLE_KEY_DATA\n-----END TACTICAL SECRET KEY-----"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_pbkdf2_migration_and_group_architecture.py:118` | `tactical` | `pw = "Tactical-Credential-Passphrase-2027"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase3_acvp_cbom_udp.py:179` | `classified` | `msg_ab = b"CLASSIFIED DEFENSE PAYLOAD: MIL-SPEC 2026 ALPHA"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase3_security_bounds.py:257` | `top secret` | `# Deniable sessions must never carry DPO (TOP SECRET) payloads.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase3_security_bounds.py:259` | `top secret` | `ch = dpo.issue_challenge("op-ts", "TOP SECRET", b"x")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase3_security_bounds.py:261` | `top secret` | `dpo.require_spo_dpo_for_send("TOP SECRET", b"x",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase3_security_bounds.py:262` | `top secret` | `{"mode": "DPO", "class": "TOP SECRET",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase3_security_bounds.py:280` | `tactical` | `# In production, deniable mode must be permitted for repudiable tactical messaging` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase4_ato_redteam_siem.py:7` | `tactical` | `4. Tactical Network Cloaking Router (Direct Public Socket Prevention)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase4_ato_redteam_siem.py:190` | `tactical` | `"""Tactical Network Cloaking & Overlay Routing Suite."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase4_ato_redteam_siem.py:193` | `tactical` | `"""Ensure direct public socket destinations are rejected under tactical cloak."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase4_ato_redteam_siem.py:212` | `tactical` | `# Public destination permitted when encapsulated through tactical overlay` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase5_csrmc_ddil_operations.py:6` | `tactical` | `2. Tactical DDIL Mesh Partition Resilience, Store-and-Forward & Merkle-DAG Delta Reconciliation` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase5_csrmc_ddil_operations.py:8` | `tactical` | `4. Multi-Node Byzantine Fault Tolerant (BFT) Quorum Consensus for Critical Tactical Commands` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase5_csrmc_ddil_operations.py:99` | `tactical` | `"""Tactical DDIL Mesh Store-and-Forward & Merkle Delta Reconciliation Suite."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase5_csrmc_ddil_operations.py:515` | `top secret` | `classification_header="// TOP SECRET // NOFORN //",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase6_cjadc2_data_fabric.py:15` | `tactical` | `- Tactical DDIL store-and-forward mesh packaging (RFC 9171 / RFC 9172)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase6_cjadc2_data_fabric.py:83` | `top secret` | `spill_payload = b"CRITICAL STRIKE ORDER // TOP SECRET // EYES ONLY"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_phase6_cjadc2_data_fabric.py:190` | `tactical` | `"""MIL-STD-6090 Cursor-on-Target Tactical Messaging Suite."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_pkcs11_token_provider.py:1` | `NC3` | `"""Tests for PKCS#11 hardware token backend and software simulation provider in NC3.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_grade_destroyer_suite.py:6` | `sovereign` | `integrated with sovereign post-quantum P2P communications.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_grade_destroyer_suite.py:36` | `destroyer` | `PROJECT_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Pa...` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_production_grade_destroyer_suite.py:186` | `classified` | `q, valid_frame = alice.seal_msg(0x01, list(b"Classified Defcon-1 Intel"))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_readiness_audit.py:6` | `zero-trust` | `1. Zero-Trust File Message Gate: file messages from unverified peers rejected fail-closed.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_surface_audit.py:23` | `destroyer` | `ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__fil...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier123_hardening.py:7` | `tactical` | `- Tier 1: Tactical DDIL BPsec AEAD enforcement (zero XOR fallback).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier4_cjadc2_and_consensus.py:15` | `tactical` | `- CJADC2 Allied Tactical Gateway Content Disarm & Reconstruction (CDR) and NOFORN Guard` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier4_cjadc2_and_consensus.py:29` | `destroyer` | `REPO_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier4_tactical_commands.py:4` | `tactical` | `Comprehensive test suite for Tier 4 tactical slash commands, Active Cyber Defense operator` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_production_tier4_tactical_commands.py:241` | `nuclear command` | `"""Test /eam and /nuclear command formatting and dispatch."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier4_tactical_commands.py:241` | `nuclear` | `"""Test /eam and /nuclear command formatting and dispatch."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier6_csprng_and_storage_audit.py:8` | `tactical` | `3. Tactical Mesh DDIL BPsec Encapsulation & CSPRNG (tactical_mesh_ddil.py).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier7_csprng_complete_audit.py:8` | `nuclear command` | `4. NC3 Nuclear Command uniform 1024-byte block padding & AEAD wire nonce` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier7_csprng_complete_audit.py:8` | `nuclear` | `4. NC3 Nuclear Command uniform 1024-byte block padding & AEAD wire nonce` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier7_csprng_complete_audit.py:8` | `NC3` | `4. NC3 Nuclear Command uniform 1024-byte block padding & AEAD wire nonce` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier7_csprng_complete_audit.py:26` | `destroyer` | `REPO_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier7_csprng_complete_audit.py:74` | `NC3` | `"""Verify NC3 wire payload padding and AEAD nonce derive from secrets."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier7_csprng_complete_audit.py:75` | `NC3` | `import nc3_nuclear_command as nc3` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_production_tier7_csprng_complete_audit.py:76` | `NC3` | `src = inspect.getsource(nc3.serialize_eam_wire)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_production_tier7_csprng_complete_audit.py:82` | `NC3` | `wire_data = nc3.serialize_eam_wire(test_payload, aead_key=key)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_proverif_st2027.py:22` | `destroyer` | `REPO_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_remediated_63_findings.py:55` | `top secret` | `msg = b"TOP SECRET MILITARY DISPATCH"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_resilient_ddil.py:1` | `tactical` | `"""DDIL resilient-communication gates (Tier-1 tactical credibility).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_core_security_suite.py:125` | `zero-trust` | `"""Prove Zero-Trust RBAC permissions and continuous risk score degradation."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_core_security_suite.py:177` | `zero-trust` | `"""Prove SecureEngine binds peer and automatically invokes ACD and Zero-Trust on replay/tamper."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_core_security_suite.py:194` | `classified` | `q, frame = initiator.seal_msg(0x01, b"classified-intel-payload")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_core_security_suite.py:276` | `zero-trust` | `# 6. Test zero-trust-eval` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_core_security_suite.py:278` | `zero-trust` | `[exe_path, "zero-trust-eval", "--peer", "operator-node", "--role", "operator", "--check-perm", "send"],` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_core_security_suite.py:291` | `top secret` | `# 1. Simple Security Property (No Read Up): Secret cannot read Top Secret` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_core_security_suite.py:296` | `top secret` | `# Top Secret CAN read Secret` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_core_security_suite.py:299` | `top secret` | `# Caveat mismatch: Top Secret without REL_TO_COALITION cannot read object requiring it` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_core_security_suite.py:305` | `top secret` | `# Secret CAN write to Secret or Top Secret` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_core_security_suite.py:314` | `top secret` | `dirty1, tag1 = zt.inspect_content(b"TOP SECRET TARGET COORDINATES")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_interop.py:182` | `tactical` | `alpha = rust_backend.get_native_group_ratchet("TACTICAL-HQ", "ALPHA", epoch_secret)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_interop.py:183` | `tactical` | `bravo = rust_backend.get_native_group_ratchet("TACTICAL-HQ", "BRAVO", epoch_secret)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_interop.py:186` | `tactical` | `assert alpha.group_id == "TACTICAL-HQ"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_interop.py:213` | `top secret` | `classified_msg = b"TOP SECRET STRATCOM DIRECTIVE 2027"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_python_crosscheck.py:37` | `destroyer` | `return HKDF(algorithm=hashes.SHA384(), length=32, salt=None, info=b"destroyer/header-protection/v2").derive(key)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_python_crosscheck.py:144` | `sovereign` | `msg = b"sovereign-payload"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_standalone_binary.py:28` | `destroyer` | `ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / "destroyer.py").exists() else Path(__fil...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_standalone_binary.py:351` | `sovereign` | `payload = b"TOP-SECRET-SOVEREIGN-ORDER-2027:" + (b"A" * 4900) + b":TERMINATE"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_rust_standalone_binary.py:683` | `top secret` | `f.write(b"TOP SECRET INTELLIGENCE DATA" * 100)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_second_audit_regressions.py:18` | `destroyer` | `ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / "destroyer.py").exists() else Path(__fil...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_security_audit_remediations.py:22` | `destroyer` | `PROJECT_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Pa...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_security_audit_remediations.py:136` | `NC3` | `"""Verify Finding 3.2: NC3 processed EAM IDs survive across controller restarts."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_security_audit_remediations.py:152` | `NC3` | `print(f"\n[PASS] Finding 3.2: NC3 EAM persistent replay journal verified across restart")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_security_audit_remediations.py:242` | `zero-trust` | `print("\n[PASS] Finding 1.1: CA zero-trust authorization whitelist and TOFU MITM detection verified")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_security_audit_remediations.py:345` | `nuclear` | `"content": "Confidential nuclear PAL message",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_sel4_sovereign_appliance.py:4` | `sovereign` | `seL4 Sovereign Hardware Appliance & MILS Separation Architecture.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_sel4_sovereign_appliance.py:121` | `tactical` | `message = b"CRITICAL TACTICAL ORDER: ALPHA FIRE"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_sel4_sovereign_appliance.py:201` | `top secret` | `secret_text = b"TOP SECRET // NOFORN // CODEWORD DESTROYER: OPERATION CLEARED"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_sel4_sovereign_appliance.py:201` | `destroyer` | `secret_text = b"TOP SECRET // NOFORN // CODEWORD DESTROYER: OPERATION CLEARED"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_simple_chat.py:80` | `tactical` | `ct = client_session.double_ratchet.encrypt(b"Tactical EAM Vector")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_simple_chat.py:82` | `tactical` | `assert pt == b"Tactical EAM Vector"  # nosec: B101` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_sovereign_group_ratchet.py:18` | `tactical` | `"""Verify encrypted group broadcast among three tactical nodes (Alpha, Bravo, Charlie)."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:42` | `top secret` | `payload = b"top secret payload"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:43` | `top secret` | `ch = ceremony.issue_challenge("op-ts-001", "TOP SECRET", payload)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:51` | `top secret` | `payload = b"TOP SECRET launch authentication payload"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:52` | `top secret` | `ch = ceremony.issue_challenge("op-ts-002", "TOP SECRET", payload)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:61` | `top secret` | `ch2 = ceremony.issue_challenge("op-ts-002b", "TOP SECRET", payload)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:65` | `top secret` | `"TOP SECRET", payload, ch2, [(h1, b1), (h2, b2)]` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:72` | `top secret` | `payload = b"TOP SECRET same officer attempt"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:73` | `top secret` | `ch = ceremony.issue_challenge("op-ts-003", "TOP SECRET", payload)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:82` | `top secret` | `payload = b"TOP SECRET replay attempt"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:83` | `top secret` | `ch = ceremony.issue_challenge("op-ts-004", "TOP SECRET", payload)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:94` | `top secret` | `ch = ceremony.issue_challenge("op-ts-005", "TOP SECRET", payload)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:99` | `top secret` | `"TOP SECRET", b"tampered payload", ch, [(h1, a1), (h2, a2)]` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:105` | `top secret` | `payload = b"TOP SECRET sync breach"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:106` | `top secret` | `ch = ceremony.issue_challenge("op-ts-006", "TOP SECRET", payload)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:136` | `top secret` | `payload = b"self-minted TOP SECRET attempt"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:141` | `top secret` | `"class": "TOP SECRET",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:146` | `top secret` | `ceremony.require_spo_dpo_for_send("TOP SECRET", payload, forged)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:152` | `top secret` | `payload = b"legitimately dual-controlled TOP SECRET"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:153` | `top secret` | `ch = ceremony.issue_challenge("op-f02-ok", "TOP SECRET", payload)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:158` | `top secret` | `out = ceremony.require_spo_dpo_for_send("TOP SECRET", payload, receipt)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:168` | `top secret` | `ch = ceremony.issue_challenge("op-f02-tamper", "TOP SECRET", payload)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:177` | `top secret` | `ceremony.require_spo_dpo_for_send("TOP SECRET", payload, bad)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:185` | `top secret` | `ceremony.require_spo_dpo_for_send("TOP SECRET", payload, bad2)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:191` | `top secret` | `ceremony.require_spo_dpo_for_send("TOP SECRET", payload, bad3)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:198` | `top secret` | `ch = ceremony.issue_challenge("op-f02-one", "TOP SECRET", payload)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_spo_dpo.py:206` | `top secret` | `ceremony.require_spo_dpo_for_send("TOP SECRET", payload, bad)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_stateful_artifact_signing.py:101` | `destroyer` | `artifact.write_bytes(b"DESTROYER-ST2027 SP 800-208 stateful signing "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:24` | `tactical` | `self.psk_path = os.path.join(self.tmp_dir, "tactical.psk")` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_acd_and_rekey.py:164` | `sovereign` | `"""secure_p2p.py runs the sovereign two-terminal tactical drill directly without deprecation."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:164` | `tactical` | `"""secure_p2p.py runs the sovereign two-terminal tactical drill directly without deprecation."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_acd_and_rekey.py:195` | `zero-trust` | `"""Continuous Zero-Trust engine tracks penalties and rewards dynamically."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:215` | `zero-trust` | `with pytest.raises(ValueError, match="zero-trust continuous verification failure"):` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:219` | `zero-trust` | `"""print_trust_status outputs continuous zero-trust metrics and score."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:223` | `zero-trust` | `assert "CONTINUOUS ZERO-TRUST POSTURE" in out` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:227` | `zero-trust` | `assert "Zero-Trust Engine: INACTIVE" in out` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:270` | `top secret` | `test_content = b"TOP SECRET MISSION PLAN: OPERATION CERBERUS STRIKE 2027\n" * 20` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:318` | `nuclear` | `"""Conversational text containing raw strategic nuclear orders is blocked by the NC3 safety gate."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:318` | `NC3` | `"""Conversational text containing raw strategic nuclear orders is blocked by the NC3 safety gate."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:325` | `nuclear` | `# Attempt to transmit strategic nuclear release command casually in chat` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:326` | `nuclear` | `result = self.node.send_chat_message("URGENT: DISPATCH NUCLEAR STRIKE ON TARGET DELTA NOW")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:327` | `nuclear` | `assert result is False, "Single-officer nuclear strike order must be blocked"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:338` | `classified` | `"""Conversational text containing classified markers is blocked when node has lower clearance."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:346` | `top secret` | `# Attempt to send TOP SECRET indicator in SECRET session` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:347` | `top secret` | `result = self.node.send_chat_message("Reviewing top secret payload telemetry")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:348` | `classified` | `assert result is False, "Classified spillage must fail-closed"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_acd_and_rekey.py:350` | `classified` | `# Legitimate routine chat without classified keywords passes guards and transmits` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_data_diode.py:3` | `tactical` | `Test Suite: Simplex Tactical Data Diode & Forward Error Correction` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_data_diode.py:9` | `tactical` | `4. Cursor-on-Target (CoT) tactical telemetry generation and serialization.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_data_diode.py:140` | `classified` | `chunk_data = b"CLASSIFIED-DIODE-PAYLOAD-BYTES-TEST"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_data_diode.py:191` | `tactical` | `# 4. CURSOR-ON-TARGET (CoT) TACTICAL TELEMETRY` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_data_diode.py:245` | `tactical` | `"""Verify tactical telemetry streaming across the diode."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_operations_suite.py:3` | `tactical` | `Unit and Integration Test Suite for Real Military Tactical C4ISR Operations.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_operations_suite.py:4` | `tactical` | `Verifies both the Native Rust Data Plane commands and Python Tactical Console:` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_operations_suite.py:6` | `tactical` | `- Tactical Message Handling (MMHS Precedence & Bell-LaPadula MLS).` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_operations_suite.py:7` | `classified` | `- NSA NCDSMO RTB Classified Spillage Prevention (Fail-Closed).` | (b) Standard Identifier | KEEP |
| `tests/test_tactical_operations_suite.py:8` | `NC3` | `- Two-Person Integrity / Dual-Custody NC3 EAM Authorization.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_operations_suite.py:31` | `tactical` | `assert BIN.exists(), f"Binary {BIN} must be built before running tactical tests."` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_operations_suite.py:76` | `tactical` | `"""Test native secure-transmit tactical-msg formats MMHS precedence correctly."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_operations_suite.py:78` | `tactical` | `[str(BIN), "tactical-msg", "--precedence", "Y", "--clearance", "TOP_SECRET", "--caveats", "NOFORN",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_operations_suite.py:89` | `classified` | `"""Test native secure-transmit tactical-msg blocks classified spillage at SECRET clearance."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_operations_suite.py:89` | `tactical` | `"""Test native secure-transmit tactical-msg blocks classified spillage at SECRET clearance."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_operations_suite.py:91` | `tactical` | `[str(BIN), "tactical-msg", "--precedence", "O", "--clearance", "SECRET", "--caveats", "NOFORN",` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_operations_suite.py:92` | `top secret` | `"--msg", "Disclosing top secret satellite frequency", "--scan-rtb"],` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_operations_suite.py:117` | `NC3` | `domain = "DESTROYER-ST2027-NC3-EAM"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_operations_suite.py:117` | `destroyer` | `domain = "DESTROYER-ST2027-NC3-EAM"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_operations_suite.py:129` | `NC3` | `self.assertIn("NC3 TWO-PERSON RULE DUAL CUSTODY VERIFIED", r_auth.stdout)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_operations_suite.py:142` | `tactical` | `"""Test full Python tactical console autonomous drill runs 100% clean."""` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_operations_suite.py:148` | `tactical` | `self.assertIn("AUTONOMOUS TACTICAL C4ISR DRILL COMPLETED WITH 100% SUCCESS", r.stdout)` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_replay.py:1` | `tactical` | `"""Behavioral tests for tactical message anti-replay protection.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_replay.py:4` | `tactical` | `to verify that identical tactical packets are rejected on second presentation,` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_web_console.py:3` | `tactical` | `Unit tests for Tactical Web Command Center API handlers.` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `tests/test_tactical_web_console.py:63` | `zero-trust` | `"""Verify GET /api/sovereignty returns zero-trust matrix."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tactical_web_console.py:71` | `classified` | `"""Verify POST /api/send formats classified chat cell."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tier4_pq_treekem_and_tfc.py:25` | `destroyer` | `REPO_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tier4_spqr_and_rum_bft.py:11` | `tactical` | `6. Clean tactical payload preservation through CDR.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tier4_spqr_and_rum_bft.py:24` | `destroyer` | `REPO_ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tier4_spqr_and_rum_bft.py:110` | `tactical` | `target = {"reason": "Hostile reconnaissance detected across tactical mesh", "target_zone": "SECTOR_7"}` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_tpm_nv_guard.py:34` | `destroyer` | `ROOT = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / 'destroyer.py').exists() else Path(__fil...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_transport_anonymity.py:273` | `top secret` | `payload = b"TOP SECRET via uniform cells"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_ts_hw_layer.py:35` | `top secret` | `# No CMVP record provisioned -> TOP SECRET refused regardless of provider.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_ts_hw_layer.py:176` | `SCIF` | `base = {"facility": "SCIF-1", "zone": 1, "level": "B", "standard": "SDIP-27/3",` | (b) Standard Identifier | KEEP |
| `tests/test_ts_hw_layer.py:180` | `top secret` | `"classifications": ["SECRET", "TOP SECRET"]}` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_ts_hw_layer.py:191` | `top secret` | `# TOP SECRET in Zone 1 needs Level A under this gate's TOP_SECRET rule.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_ts_hw_layer.py:193` | `top secret` | `ts.require_tempest_approval(1, "TOP SECRET", reg)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_ts_hw_layer.py:195` | `top secret` | `assert ts.require_tempest_approval(0, "TOP SECRET", reg_a).level == "A"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_ts_hw_layer.py:199` | `top secret` | `ts.require_tempest_approval(0, "TOP SECRET", reg_b)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_ts_hw_layer.py:446` | `top secret` | `"classifications": ["TOP SECRET"]}]}))` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_ts_hw_layer.py:690` | `top secret` | `ts.require_hardware_custody("TOP SECRET session keys")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_ts_runtime.py:371` | `destroyer` | `root = Path(__file__).resolve().parent if (Path(__file__).resolve().parent / "destroyer.py").exists() else Path(__fil...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_unified_secure_pipeline.py:85` | `classified` | `data = b"CLASSIFIED DIRECTIVE ALPHA-7"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_unified_secure_pipeline.py:166` | `NC3` | `plaintext = b"NC3/EAM: AUTHENTICATE DELTA-SEVEN-NINER"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_unified_secure_pipeline.py:192` | `top secret` | `plaintext = b"TOP SECRET COORDINATES: 38.8977 N, 77.0365 W"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_unified_secure_pipeline.py:219` | `destroyer` | `salt=b"destroyer-p2p-rust-v1", info=b"destroyer/frame/v1")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tests/test_unified_secure_pipeline.py:311` | `tactical` | `msg = f"Tactical Cover/Chat Packet #{i}".encode("utf-8")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `threat_detection_response_system.py:3` | `zero-trust` | `Zero-Trust Anomaly Analysis and Active Defense Subsystem` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:526` | `maximum security` | `# Prefer the full hybrid KEx for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:560` | `maximum security` | `# Prefer the full hybrid KEx for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:597` | `maximum security` | `# Prefer the full hybrid KEx for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:1210` | `sovereign` | `# Enforce sovereign isolation in production mode` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:1213` | `sovereign` | `log.error(f"MILITARY FATAL: Public cloud OAuth provider '{self.provider_name}' is forbidden in sovereign production m...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:1215` | `sovereign` | `f"Public cloud OAuth provider '{self.provider_name}' prohibited in sovereign production mode. "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:1259` | `sovereign` | `f"OAuth device flow for '{self.provider_name}' is blocked in sovereign production mode."` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:1406` | `destroyer` | `'User-Agent': 'Destroyer-ST2027-SecurityPipeline/1.0',` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:1489` | `zero-trust` | `CNSA 2.0 / Zero-Trust Requirement:` | (b) Standard Identifier | KEEP |
| `tls_channel_manager.py:1500` | `sovereign` | `# Block public cloud OAuth in sovereign production mode` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:1502` | `sovereign` | `msg = f"Public OAuth validation for '{self.provider_name}' prohibited in sovereign production mode"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:1524` | `destroyer` | `'User-Agent': 'Destroyer-ST2027-SecurityPipeline/1.0',` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:2113` | `sovereign` | `# Set up OAuth authentication if explicitly enabled (Disabled by default for sovereign mode)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:2451` | `maximum security` | `"message": "BONUS: Successfully using post-quantum ciphers for maximum security"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:2890` | `maximum security` | `# Use the hybrid KEM from pqc_algorithms for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:2944` | `maximum security` | `length=64,  # 64 bytes for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:3778` | `maximum security` | `# For maximum security, always enable certificate verification by default` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:3787` | `maximum security` | `# Fall back to system CA store for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:3837` | `maximum security` | `# ONLY use the enhanced hybrid key exchange for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:4554` | `tactical` | `raise SecurityError("Disabling client certificate verification (CERT_NONE) on TLS server is strictly prohibited under...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:4585` | `maximum security` | `# Maximum security: Only allow strongest post-quantum and modern groups, no legacy curves.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:5379` | `maximum security` | `algorithm=hashes.SHA3_512(),  # Use SHA3_512 for maximum security` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `tls_channel_manager.py:6362` | `tactical` | `raise SecurityError("Disabling client certificate verification (CERT_NONE) on TLS server is strictly prohibited under...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:3` | `top secret` | `transport_anonymity.py — Network transport and anonymity for TOP SECRET` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:9` | `top secret` | `or TOP SECRET mode. Allowed paths are Tor v3 onion routing via a live` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:11` | `sovereign` | `proxy so no local DNS leak), or a sovereign path (private APN /` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:14` | `tactical` | `by policy engine plus tactical cloak plus peer-prefix gates composed here.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:31` | `sovereign` | `Software cannot conjure sovereign dark fiber, certified mixnet` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:222` | `top secret` | `Strict (production or TOP SECRET) policy:` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:227` | `sovereign` | `sovereign modes additionally require overlay-active flag plus a` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:242` | `tactical` | `# Strict: compose the deployed policy engine with the tactical cloak` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:383` | `sovereign` | `log.debug("sovereign dial refused: %r", exc)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:536` | `sovereign` | `ordered (TCP via Tor or sovereign path): every emitted cell, real or` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:685` | `destroyer` | `info=b"DESTROYER-ANON-EPOCH-RATCHET-v2",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:797` | `top secret` | `classification: str = "TOP SECRET",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:808` | `sovereign` | `overlay (Tor onion/proxy or attested sovereign path), so deep packet` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:819` | `top secret` | `norm = " ".join(str(classification or "TOP SECRET").strip().upper().split())` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:820` | `top secret` | `if norm != "TOP SECRET":` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `transport_anonymity.py:974` | `top secret` | `classification: str = "TOP SECRET",` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:987` | `top secret` | `norm = " ".join(str(classification or "TOP SECRET").strip().upper().split())` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `transport_anonymity.py:988` | `top secret` | `if norm != "TOP SECRET":` | (c) Identifier / File Name | RENAME_OR_KEEP |
| `triple_hybrid_kem.py:248` | `maximum security` | `- Conservative parameters for maximum security margin` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `trust_anchor.py:4` | `top secret` | `TOP SECRET transmission (2027 target posture, item #5).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `trust_anchor.py:12` | `top secret` | `canonical TBS. In strict mode (TOP SECRET or production) there is no` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `trust_anchor.py:25` | `top secret` | `EPHEMERAL: zero-plaintext-disk profile for the TOP SECRET path. When` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `trust_anchor.py:36` | `top secret` | `amnesia doctrine). What is enforced here: no TOP SECRET-path write of` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `trust_anchor.py:47` | `NC3` | `and NC3 doctrines already in the repo.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:3` | `top secret` | `ts_hw_layer.py — Hardware & Physical Security gating layer for TOP SECRET /` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:9` | `TEMPEST shielding` | `Level 3/4 tamper envelope, TEMPEST shielding, RED/BLACK electrical isolation,` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:19` | `top secret` | `build. Refuses TOP SECRET operation on software-only Level-1` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:30` | `top secret` | `SDIP-29 installation references) before TOP SECRET processing, and` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:57` | `classified` | `is classified; cf. Antic et al., Appl. Sci. 2024).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:120` | `top secret` | `"""Raised when TOP SECRET operation is attempted on unqualified platform."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:308` | `top secret` | `"""Fail-closed FIPS gate for TOP SECRET operation."""` | (b) Standard Identifier | KEEP |
| `ts_hw_layer.py:312` | `top secret` | `"no FIPS 140-3 provider loaded in this OpenSSL — TOP SECRET "` | (b) Standard Identifier | KEEP |
| `ts_hw_layer.py:378` | `top secret` | `"""Fail-closed, tiered custody gate for TOP SECRET key material.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:392` | `top secret` | `Rationale (FIPS 140-3 L3/L4 + Type 1 baseline): at TOP SECRET, plaintext` | (b) Standard Identifier | KEEP |
| `ts_hw_layer.py:405` | `top secret` | `f"mesh covers in-use keys — TOP SECRET data plane refused")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:412` | `top secret` | `f"exist in CPU RAM — TOP SECRET operation refused (FIPS 140-3 "` | (b) Standard Identifier | KEEP |
| `ts_hw_layer.py:656` | `top secret` | `TOP_SECRET_MIN_LEVEL = "A"   # TOP SECRET processing requires Level A equipment` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:671` | `top secret` | `classifications: Tuple[str, ...] = ("TOP SECRET",)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:689` | `top secret` | `classes = c.get("classifications", ["TOP SECRET"])` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:713` | `top secret` | `the intended operation — and refuses TOP SECRET processing otherwise.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:720` | `top secret` | `raise TSRequiredError("no TEMPEST registry provisioned — TOP SECRET refused")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:721` | `top secret` | `need = TOP_SECRET_MIN_LEVEL if classification.strip().upper() == "TOP SECRET" \` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:743` | `top secret` | `f"(need Level {need}+ with SDIP-28/29 refs) — TOP SECRET refused")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:1073` | `top secret` | `never exist in any production or TOP SECRET posture.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:1132` | `top secret` | `Software simplex alone is NEVER sufficient at TOP SECRET.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:1137` | `top secret` | `raise TSRequiredError("no diode registry provisioned — TOP SECRET refused")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:1153` | `top secret` | `f"single-interconnect record, unexpired) — TOP SECRET refused")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:1296` | `top secret` | `# Aggregator: full TOP SECRET hardware-layer preflight` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:1302` | `top secret` | `classification: str = "TOP SECRET"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:1324` | `top secret` | `classification=os.environ.get("P2P_TS_CLASS", "TOP SECRET"),` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:1339` | `top secret` | `"""Full TOP SECRET hardware-layer preflight. First failure aborts.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:1350` | `top secret` | `# TOP SECRET mandates an ARMED mesh; auto-provision one bound to this` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_hw_layer.py:1366` | `top secret` | `custody = require_hardware_custody("TOP SECRET session keys", mesh=mesh)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_runtime.py:87` | `top secret` | `"""TOP SECRET operation refused on unqualified runtime/platform."""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_runtime.py:657` | `top secret` | `"TOP SECRET refused (seL4 verified config or AO waiver required)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_runtime.py:673` | `top secret` | `f"TOP SECRET refused")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_runtime.py:708` | `top secret` | `f"boot chain unqualified ({', '.join(failures)}) — TOP SECRET refused")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_runtime.py:828` | `top secret` | `"DMA device scan failed — posture unverifiable, TOP SECRET refused")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_runtime.py:835` | `top secret` | `"DMA device scan failed — posture unverifiable, TOP SECRET refused")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_runtime.py:857` | `top secret` | `f"({len(unaccepted)} found) — TOP SECRET refused; remediation: "` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ts_runtime.py:864` | `top secret` | `f"TOP SECRET refused; name instance IDs in waiver dma_accepted or remove")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ui/display.py:50` | `sovereign` | `auth_mode = "[OK] Strict Sovereign PKI (ML-DSA-87)" if getattr(self.orchestrator, 'strict_auth', True) else "[--] Ano...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ui/display.py:285` | `maximum security` | `security warnings and ensure maximum security for their application.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ui/display.py:304` | `maximum security` | `print(" [OK] Hardware DEP is enabled (Maximum security)")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ui/display.py:328` | `maximum security` | `print("   - Recommendation: Run this application as administrator for maximum security")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ui/display.py:450` | `tactical` | `# 8. DoD CSRMC Phase 5 Operations & Tactical DDIL Resilience` | (b) Standard Identifier | KEEP |
| `ui/display.py:451` | `tactical` | `print("[DEFENSE] DOD CSRMC PHASE 5 OPERATIONS & TACTICAL DDIL RESILIENCE")` | (b) Standard Identifier | KEEP |
| `ui/display.py:456` | `tactical` | `# 9. CJADC2 Tactical Data Fabric & Crypto-Agility (Phase 6)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ui/display.py:457` | `tactical` | `print("[NETWORK] CJADC2 TACTICAL DATA FABRIC & CRYPTO-AGILITY")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ui/display.py:471` | `tactical` | `"""Display DoD CSRMC Phase 5 continuous operations & DDIL tactical status."""` | (b) Standard Identifier | KEEP |
| `ui/display.py:495` | `tactical` | `print(f"  * Tactical DDIL Mesh      : RFC 9171 / RFC 9172 BPsec ({mesh.total_bundles_stored} stored, {mesh.total_bund...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `ui/display.py:518` | `tactical` | `print(f"  * Tactical Messaging      : MIL-STD-6090 Cursor-on-Target (CoT) ML-DSA-87 Signed")` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `unified_secure_pipeline.py:5` | `destroyer` | `Chains every security layer in the Destroyer ST2027 architecture so that` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `unified_secure_pipeline.py:60` | `destroyer` | `LAYER2_HKDF_SALT = b"destroyer-p2p-rust-v1"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `unified_secure_pipeline.py:61` | `destroyer` | `LAYER2_HKDF_INFO = b"destroyer/frame/v1"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `unified_secure_pipeline.py:62` | `destroyer` | `CER_HKDF_SALT = b"destroyer-cer-epoch-v1"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `unified_secure_pipeline.py:329` | `NC3` | `msg_type: Message type tag (MSG, FILE, NC3).` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `unified_secure_pipeline.py:637` | `destroyer` | `RATCHET_SALT = b"destroyer-autonomous-ratchet-v1"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `unified_secure_pipeline.py:638` | `destroyer` | `STEP_SALT = b"destroyer-ratchet-step-v1"` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `utils/config_manager.py:1014` | `zero-trust` | `# Fail-closed invariants (military zero-trust): any violation is fatal.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `utils/error_handler.py:325` | `sovereign` | `# Sovereign / nuclear default: zero plaintext disk persistence of unsent queues` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `utils/error_handler.py:325` | `nuclear` | `# Sovereign / nuclear default: zero plaintext disk persistence of unsent queues` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `verify_intercontinental_udp_stream.py:69` | `tactical` | `100,             # 100 Bytes (tactical alert)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `verify_intercontinental_udp_stream.py:72` | `tactical` | `1024 * 1024,     # 1 MB (tactical audio / imagery)` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `zero_trust_assessment.py:6` | `sovereign` | `Evaluates the Sovereign Military Communications Platform against the 7 Pillars of the` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `zero_trust_assessment.py:12` | `tactical` | `5. Network & Environment: Tactical network cloaking, WireGuard UDP overlay, 0x direct public sockets` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `zero_trust_assessment.py:214` | `tactical` | `{"id": "N.1", "name": "Tactical Network Cloaking", "implemented": True, "details": "Prohibition of unencapsulated dir...` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `zero_trust_engine.py:3` | `zero-trust` | `Zero-Trust Authentication Engine - Strict Verification` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `zero_trust_engine.py:5` | `zero-trust` | `This module implements zero-trust authentication with session termination` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `zero_trust_engine.py:169` | `zero-trust` | `Zero-Trust Role-Based Access Control (RBAC) Engine.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `zero_trust_engine.py:266` | `zero-trust` | `"""Session states for zero-trust authentication"""` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `zero_trust_engine.py:306` | `zero-trust` | `Zero-Trust Authentication Engine with Strict Verification` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `zero_trust_engine.py:320` | `zero-trust` | `Initialize Zero-Trust Engine.` | (a) Promotional / Overclaiming Phrase | REPLACE |
| `zero_trust_engine.py:403` | `zero-trust` | `message=f"Zero-Trust Auth: {operation} - {result}",` | (a) Promotional / Overclaiming Phrase | REPLACE |
