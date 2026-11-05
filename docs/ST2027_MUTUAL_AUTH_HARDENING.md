# ST2027 Production Mutual-Authentication Hardening

Status: implemented in the canonical `secure_p2p.py node` path and the native
`secure-transmit` KEX engine. This document records the protocol, the
research basis, the tests that exercise it, and the residual risks that no
software-only change can remove.

## 1. Scope

The production network entry point is:

```text
secure_p2p.py node --role initiator|responder \
  --psk-file FILE \
  --auth-sk-file FILE \
  --peer-auth-pk-file FILE \
  [--require-mutual-auth]
```

`--auth-sk-file` is the local ML-DSA-87 signing seed (32 bytes, hex, owner-only).
`--peer-auth-pk-file` is the pinned peer ML-DSA-87 public key (2592 bytes, hex).
The PSK remains a second, independent factor. Outside explicit `--lab` mode the
Python entry point refuses to start without both identity files, and the Rust
engine independently requires mutual authentication unless `P2P_LAB_MODE=1` is
set. `--require-mutual-auth` pins mutual authentication on even if a lab
variable is present.

The following surfaces are **not** part of the production path and are refused
while the production gate is armed:

- `demo`, `chat`, `monolith`, `web` (all require `--lab`);
- simulated `/eam`, `/nc3-verify`, and `/ptt` commands (refused at the
  interactive terminal in production);
- PSK-only KEX (lab fallback only; lower assurance).

## 2. Algorithms and standards

| Function | Algorithm | Standard / basis |
|---|---|---|
| Hybrid KEX | SecP384r1MLKEM1024 (P-384 ECDH + ML-KEM-1024) | RFC 10024 hybrid construction; FIPS 203; CNSA 2.0 |
| Identity signatures | ML-DSA-87 | FIPS 204; CNSA 2.0 |
| AEAD | AES-256-GCM | FIPS 197; SP 800-38D; CNSA 2.0 |
| Hash / KDF | SHA-384, HKDF-SHA384, HMAC-SHA384 | FIPS 180-4; SP 800-56C; CNSA 2.0 |
| PSK | 32 bytes, file/stdin only, never argv | CNSA 2.0 defense in depth |
| SAS | 128-bit, SHA-384 derived | Out-of-band confirmation |

Research basis used for the design:

- **NIST IR 8547 (2026):** quantum-vulnerable algorithms are deprecated after
  2030 and disallowed after 2035; new national-security systems should use
  CNSA 2.0.
- **CNSA 2.0 FAQ / CNSSP 15:** ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512;
  new NSS acquisitions from 2027 and mandatory protocol use by 2031.
- **RFC 10024:** PQ/T hybrid key establishment; the session remains safe while
  at least one component holds.
- **Signal PQXDH analyses (Fiedler/Guenther PKC 2025; Bhargavan USENIX 2024):**
  bind the KEM ciphertext to the encapsulation key and hash every transmitted
  bundle into the transcript.
- **Side-channel literature:** KyberSlash, CT-KAT (ePrint 2026/1418), masked
  ML-KEM shuffling (ePrint 2026/934), and ML-DSA division-timing analyses.
  These motivate constant-time validation and independent review; they are not
  solved by protocol changes alone.
- **Trail of Bits constant-time PQC guidance:** treat upstream `ml-kem` /
  `ml-dsa` crates as unaudited until independently validated on the target
  hardware.

## 3. Wire protocol

Bundle sizes are fixed, so every field is unambiguous:

```text
responder_bundle = p384_pub(97) || ml_kem_ek(1568)        = 1665 bytes
initiator_bundle = eph_p384_pub(97) || ml_kem_ct(1568)   = 1665 bytes
transcript       = SHA-384(responder_bundle || initiator_bundle)   (48 bytes)
```

Mutual-authentication flow (production):

```text
R -> I : responder_bundle
I -> R : initiator_bundle
both   : transcript = SHA-384(responder_bundle || initiator_bundle)
R -> I : responder_sig = ML-DSA-87.Sign(DOMAIN_SIG_RESPONDER, transcript)
I      : verify responder_sig with pinned peer key; abort on failure
I -> R : initiator_sig = ML-DSA-87.Sign(DOMAIN_SIG_INITIATOR, transcript)
R      : verify initiator_sig with pinned peer key; abort on failure
both   : binding = SHA-384("ST2027-KEX-v2::auth-binding"
                           || transcript
                           || len(responder_sig) || responder_sig
                           || len(initiator_sig) || initiator_sig)
both   : session_key = HKDF-SHA384(hybrid_ss,
                                   salt = PSK,
                                   info = domain || binding)
R -> I : resp_confirm = HKDF-SHA384(session_key, "RESPONDER-CONFIRM" || binding)
I      : verify resp_confirm; abort on failure
I -> R : init_confirm = HKDF-SHA384(session_key, "INITIATOR-CONFIRM" || binding)
R      : verify init_confirm; abort on failure
both   : SAS = SHA-384(session_key || binding)[..16]
```

The responder verifies the initiator's signature **before** deriving the
session key. The initiator verifies the responder's signature **before** sending
its own signature or deriving the key. Both sides then exchange key-confirmation
tags. The PSK is an HKDF salt, so a wrong PSK produces a different key and a
confirmation-tag mismatch.

Because the binding covers both signatures and is fed to the KDF, an attacker
cannot strip, replace, or downgrade the signature legs without changing the
session key and SAS.

## 4. Python control-plane hardening

- `_validate_auth_material()` checks exact hex lengths (64 chars for the seed,
  5184 for the peer public key), rejects non-hex, and enforces owner-only mode
  on the signing seed on POSIX. It refuses identical signing/public-key paths.
- `_production_crypto_violations()` refuses known weakening environment
  overrides before any network activity: `P2P_ALLOW_CLASSICAL`,
  `P2P_ALLOW_INSECURE_PLAINTEXT`, `P2P_ALLOW_UNVERIFIED_TOFU`,
  `P2P_ALLOW_INSECURE_DANE_BYPASS`, `P2P_ALLOW_UNKEYED_CHUNKS`,
  `P2P_ALLOW_LEGACY_CERTS`, `P2P_ALLOW_LEGACY_KEY_MIGRATION`,
  `P2P_ALLOW_LEGACY_AUDIT_CHAIN`, `P2P_ALLOW_LEGACY_WORM_CHAIN`,
  `P2P_ALLOW_SOFTWARE_FALLBACK`, and `P2P_REQUIRE_AUTH=0`.
- `TacticalP2PNode.negotiate_hybrid_kex()` passes the identity files to the Rust
  engine and removes `P2P_LAB_MODE` / `ST2027_LAB_MODE` from the child
  environment when mutual authentication is selected.
- The interactive terminal shows a crypto-posture block in `/status`
  (KEX group, identity authentication, mutual-auth state, AEAD, hash/KDF, PSK)
  and refuses simulated NC3/EAM/PTT commands in production.

## 5. Verification evidence

The implementation is exercised by:

- `cargo test --lib --bins` — 148 Rust unit tests, including KEM, ML-DSA-87,
  AEAD, replay, ratchet, keystore, and TPM-state tests.
- `tests/test_rust_standalone_binary.py::test_kex_mutual_mldsa87_authentication`
  — real two-process mutual-auth KEX, key agreement, output labels, and a
  wrong-pin negative test that writes no session key.
- `tests/test_secure_p2p_military_entrypoint.py` — production entry-point
  refusals (missing PSK, missing mutual-auth material, malformed keys, weak
  environment overrides), help surface, and the production selftest.
- `secure_p2p.py selftest` — includes a live loopback
  SecP384r1MLKEM1024 + PSK + mutual ML-DSA-87 KEX.
- An end-to-end two-node test drives the real interactive production path:
  both nodes establish the channel, exchange an encrypted message, and exit
  cleanly with the simulated surfaces disabled.

Negative cases covered:

- wrong PSK → confirmation-tag mismatch, no key file written;
- wrong pinned peer key → signature verification failure, no key file written;
- missing/oversized/non-hex identity files → fail-closed before networking;
- weak crypto environment override → production refusal;
- tampered ML-KEM ciphertext → different shared secret (implicit rejection);
- tampered AEAD frame / replay / rollback → rejected by the Rust data plane.

## 6. Residual risks and non-claims

This is strong, standards-based engineering, not a guarantee of
"nuclear-code" security.

1. **No independent audit / certification.** The Rust `ml-kem` and `ml-dsa`
   crates are upstream-unaudited. This code has not passed FIPS 140-3 CMVP,
   Common Criteria, or a third-party cryptographic review. Do not represent it
   as certified.
2. **Side channels.** Protocol-level binding does not prove constant-time
   behaviour on the target CPU. Timing/cache/power analysis of ML-KEM, ML-DSA,
   P-384, and AES must be evaluated on the actual hardware, with masking,
   constant-time validation, and independent lab testing.
3. **Hardware custody.** Software key files are not a root of trust. TOP SECRET
   deployments need TPM/HSM-backed non-exportable keys, measured boot,
   attested PCR state, two-person integrity, and a witnessed key ceremony.
   `--require-hardware` can enforce the project's readiness checks, but the
   checks themselves are not a certification.
4. **Endpoint compromise.** Malware, debuggers, DMA, swap/hibernation, and
   screen capture can defeat any transport cryptography. TEMPEST/RF shielding,
   physical access control, and trusted operating systems are outside this
   repository.
5. **Metadata.** The KEX uses TCP and the channel uses UDP with constant-rate
   pacing. Pacing reduces timing/size leakage but does not hide the existence
   of the endpoints or defeat a global passive adversary.
6. **Post-compromise healing status (updated).** The Python outer ratchet evolves
   per message (forward secrecy). The Rust `channel` uses one session frame key
   for the session lifetime; the fresh-KEM `ratchet.rs` (`PcsRatchet` /
   `CoreRatchet`) is available but is not yet wired into the production
   channel, so full Signal-style PCS is NOT claimed. In-band CER epoch
   rotation now mixes best-effort entropy and is honestly labelled
   "best-effort PCS"; true healing requires a fresh authenticated KEX rekey
   (tracked as a follow-up, not yet implemented).
7. **Simulated features remain in the tree but are now compile-time gated.**
   NC3/EAM/PTT/CoT code still exists for lab exercises and is refused on the
   production path. Production Rust builds MUST use `--no-default-features`
   so the simulated command surfaces are absent from the binary entirely;
   default builds retain them for lab use only. They must never be used for
   real command-and-control.
8. **Hardware custody is armed by default in production.** `secure_p2p.py node`
   now treats production mode as requiring hardware readiness and sets
   `P2P_FAIL_ON_SOFTWARE_FALLBACK=1`, so software-key fallback is refused
   unless an explicit lab override is supplied. This is a policy gate, not a
   certification of the underlying TPM/HSM.
8. **Operational discipline.** SAS comparison, key rotation, revocation,
   incident response, audit retention, and separation of duties are operator
   responsibilities.

## 7. References

- NIST IR 8547 (2026), *Transition to Post-Quantum Cryptography Standards*.
- NSA CNSA 2.0 FAQ and CNSSP 15.
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 197 (AES), FIPS 180-4 (SHA).
- NIST SP 800-38D (GCM), SP 800-56C (KDF), SP 800-207 (zero trust).
- RFC 10024, *PQ/T Hybrid Key Establishment*.
- Fiedler & Guenther, PKC 2025; Bhargavan et al., USENIX Security 2024
  (PQXDH analyses).
- ePrint 2026/1418 (CT-KAT), ePrint 2026/934 (masked ML-KEM shuffling),
  KyberSlash disclosures.
- Trail of Bits, *Constant-Time PQC* guidance.

## 8. Zero-Disk Key Containment & Hardware Key Custody (2026/2027 Standards)

### 8.1 Threat Model: Eliminating Disk-Based Signing Seeds
File-based signing seeds (`--auth-sk-file`) stored on host filesystem disks remain vulnerable to physical acquisition, host root compromise, and unencrypted cold storage extraction. Zero-Disk Key Containment guarantees that no raw signing seeds ever reside in plaintext on persistent host media.

### 8.2 Native PKCS#11 HSM Architecture (Rust Data Plane)
Direct hardware signing is integrated natively into `rust_data_plane` via the `cryptoki` crate (PKCS#11 v3.1):
- **Function**: `destroyer_core::auth::sign_with_hsm(session: &Session, key_handle: ObjectHandle, digest: &[u8]) -> Result<Vec<u8>, HsmError>`
- **Hardware Targets Supported**:
  - **YubiKey 5 FIPS**: `ykcs11` driver (`libykcs11.so` / `ykcs11.dll`)
  - **Thales Luna PCIe HSM**: `libCryptoki2_64.so` / `Crystoki.dll`
  - **Nitrokey HSM**: OpenSC PKCS#11 (`opensc-pkcs11.so` / `opensc-pkcs11.dll`)
- **Algorithms**: FIPS 204 ML-DSA-87 (`Mechanism::MlDsa`), ECDSA (P-384), Pure Ed25519 (`EddsaParams`), RSA-PSS.
- **Probe Command**: `secure-transmit hsm-probe` inspects standard driver candidate paths across Windows, Linux, and macOS.

### 8.3 TPM 2.0 PCR-Sealed Identity Storage
Nodes utilize TCG TPM 2.0 Part 1/2 measured boot object sealing via `destroyer_core::tpm_nv`:
- **Sealing**: `secure-transmit auth-tpm-seal --seed-file <PATH> --out-priv <PATH> --out-pub <PATH> --pcrs 0,1,2,7`
  - The plaintext seed file is ingested into page-locked RAM and immediately wiped from disk (3-pass NIST SP 800-88 purge).
  - The seed is sealed against measured boot registers:
    - **PCR 0**: CRTM, BIOS / UEFI firmware code & embedded measurements
    - **PCR 1**: Host Platform Configuration & motherboard hardware
    - **PCR 2**: UEFI Option ROMs (PCIe devices, RAID, NIC firmware)
    - **PCR 7**: Secure Boot State, PK, KEK, db, dbx, and policy enforcement
- **Unsealing & KEX**:
  - `secure-transmit kex-listen --auth-tpm-sealed <PRIV> [--auth-tpm-pub <PUB>] --peer-auth-pk-file <PEER_VK> ...`
  - `secure-transmit kex-connect --auth-tpm-sealed <PRIV> [--auth-tpm-pub <PUB>] --peer-auth-pk-file <PEER_VK> ...`
  - In `secure_p2p.py node`: `--auth-tpm-sealed <PRIV>` directly substitutes for `--auth-sk-file`.
  - **Fail-Closed Policy Enforcement**: If firmware is tampered with or Secure Boot is disabled, TPM silicon returns `TPM_RC_POLICY_FAIL` (0x99D), and the data plane aborts execution without unsealing the identity key.

### 8.4 Two-Person Integrity (TPI) Split-Knowledge Doctrine
Under DoD S-5210.41M, high-consequence operations (Emergency Action Messages `/eam`, Push-to-Talk bursts `/ptt`, and NC3 directives) require physical split-knowledge smartcard tokens:
- **Production Doctrine**: Disk-based synthetic JSON signature files are strictly prohibited outside `--lab` mode.
- **Hardware Ceremony**: `secure-transmit eam-auth-hw` co-signs the canonical EAM wire bytes via two independent physical hardware tokens (`--token1-module`, `--token2-module`).
- Both officers must be distinct authorized operators holding enrolled hardware tokens.
