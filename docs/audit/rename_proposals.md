# Proposed Architectural and Symbol Renames

This document catalogs proposed renames for file names, module names, classes, functions, and environment variables containing prohibited or sensational terminology where direct in-place renaming risks breaking signed hash trees, external CI invocation scripts, or cross-language FFI bindings.

Per **Stage B Rule 3**, where renaming an identifier requires extensive multi-repo or external script updates, the rename proposal is formally documented here with its exact technical replacement and migration plan.

---

## 1. File Name Renaming Proposals

| Current File Path | Proposed Replacement Path | Technical Mechanism & Purpose | Risk / Blast Radius & Dependencies |
|---|---|---|---|
| `destroyer.py` | `p2p_cli.py` or `mesh_orchestrator.py` | Multi-terminal CLI launcher and configuration controller | Referenced in `.github/workflows/defense_ci.yml`, batch scripts (`launch_tactical_web.bat`), and test runners. |
| `destroyer_node.py` | `mesh_node.py` | High-level peer-to-peer network node implementation | Referenced across integration tests and runtime dispatchers. |
| `maximum_security_hardening.py` | `system_security_hardening.py` | Win32 exploit mitigations (DEP, ASLR, ACG, CFG) and process policies | Imported by `security_framework` and system hardening tests. |
| `tactical_data_diode.py` | `simplex_udp_stream.py` | Unidirectional UDP socket transmitter with Cauchy-RS forward error correction | Software simplex stream; cannot provide physical optical isolation. |
| `cjadc2_tactical_cot.py` | `cjadc2_cot_telemetry.py` | Cursor-on-Target MIL-STD-6090 XML and compact JSON telemetry serializer | Imported by CJADC2 test suites and allied gateway handlers. |
| `certs/sovereign_root_ca.json` | `certs/root_ca.json` | Local PKI trust anchor root certificate containing ML-DSA-87 public key | **BLOCKED:** Hash recorded in `certs/pki_manifest.json` and signed with private key. |
| `certs/sovereign_sub_ca.json` | `certs/sub_ca.json` | Intermediate issuing CA certificate | **BLOCKED:** Hash recorded in `certs/pki_manifest.json` and signed with private key. |

---

## 2. Class and Symbol Renaming Proposals

| Current Symbol | Location | Proposed Replacement | Factual Rationale |
|---|---|---|---|
| `class MilitaryGradeCrypto` | `secure_p2p.py:520` | `class SymmetricCryptoEngine` | Standard library AES-256-GCM and SHA-256 wrapper. |
| `def _add_military_grade_padding` | `core/orchestrator.py:180` | `def _add_quantized_padding` | Power-of-two / 1232-byte uniform packet padding. |
| `def _generate_military_auth_tag` | `core/orchestrator.py:210` | `def _generate_hmac_auth_tag` | Standard HMAC-SHA384 authentication tag computation. |
| `class NC3CommandController` | `critical_release.py:45` | `class DualAuthorizationController` | Dual-officer two-person integrity threshold verification within 2.0-second window. |
| `class SovereignGroupRatchet` | `rust_data_plane/src/group_ratchet.rs:12` | `class GroupRatchetEngine` | Multi-party ratchet engine maintaining per-peer monotonic symmetric chains. |
| `class DestroySession` | `secure_p2p.py:890` | `class TerminateSession` | Routine closing sockets and invoking memory zeroization on local key buffers. |

---

## 3. Environment Variable Renaming Proposals

| Current Environment Variable | Proposed Replacement | Scope & Default |
|---|---|---|
| `P2P_TEMPEST_REGISTRY` | `P2P_EMISSIONS_ACCREDITATION_FILE` | Path to operator-supplied emissions-security record; software does not measure physical shielding. |
| `P2P_NC3_MODE` | `P2P_DUAL_AUTH_REQUIRED` | Boolean flag enforcing 2-of-2 officer cryptographic signatures on privileged control messages. |
| `P2P_TACTICAL_KEY_PW` | `P2P_OPERATOR_PASSPHRASE` | Passphrase used to decrypt local PKCS#8 / PKCS#12 private key stores. |
| `P2P_SOVEREIGN_ROOT_CA` | `P2P_ROOT_CA_FILE` | Path to root CA certificate JSON file. |
