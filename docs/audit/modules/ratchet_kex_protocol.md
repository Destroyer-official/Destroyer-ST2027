# Module Documentation: Ratchet and Key Exchange Protocol Subsystem (`ratchet_kex_protocol`)

## 1. Module Name & Purpose

- **Module Name:** `ratchet_kex_protocol`
- **Subsystem Classification:** Key Exchange, Forward Secrecy, Post-Quantum Ratcheting, and Group Agreement
- **Files in Module (10 files, 15,437 verified lines):**
  - `noise_pq.py` (987 lines)
  - `hybrid_kex.py` (3,467 lines)
  - `double_ratchet.py` (5,709 lines)
  - `forward_secrecy_manager.py` (755 lines)
  - `triple_hybrid_kem.py` (1,321 lines)
  - `group_key_manager.py` (1,741 lines)
  - `[ISOLATED]_group_ratchet.py` (264 lines)
  - `treekem.py` (362 lines)
  - `pq_treekem.py` (444 lines)
  - `mls_framing.py` (387 lines)

- **Primary Technical Purpose:**
  The `ratchet_kex_protocol` module implements session negotiation, ephemeral key encapsulation, two-party and multi-party ratchet state machines, forward secrecy guarantees, and tree-based group key agreements. It integrates post-quantum algorithms (ML-KEM-1024, Classic McEliece, FrodoKEM-1344) with classical elliptic-curve Diffie-Hellman (P-384, X25519) and signature schemes (ML-DSA-87, SLH-DSA-256f).

---

## 2. Public Interface

### 2.1. `noise_pq.py`
- **Classes:**
  - `NoiseError(Exception)` (`:44`): Base exception for handshake failures, MAC discrepancies, and state violations.
  - `SymmetricState` (`:123`): Encapsulates chaining key ($ck$) and handshake hash ($h$) utilizing SHA-384 and AES-256-GCM.
    - `mix_key(input_key_material: bytes)` (`:137`)
    - `mix_hash(data: bytes)` (`:147`)
    - `mix_key_and_hash(input_key_material: bytes)` (`:156`)
    - `encrypt_and_hash(plaintext: bytes) -> bytes` (`:167`)
    - `decrypt_and_hash(ciphertext: bytes) -> bytes` (`:179`)
    - `split() -> Tuple[CipherState, CipherState]` (`:191`)
  - `NoiseSession` (`:204`): Handshake controller executing `Noise_XXhfs` state machine.
    - `write_message(payload: bytes = b"") -> bytes` (`:230`)
    - `read_message(message: bytes) -> bytes` (`:285`)
  - `StatelessCookieGate` (`:420`): SYN-flood mitigation verifying cryptographic cookies prior to handshake state allocation.

### 2.2. `hybrid_kex.py`
- **Classes:**
  - `HybridKeyExchange` (`:674`): Session coordinator managing identity bundles and ephemeral exchanges.
    - `get_public_bundle() -> Dict[str, Any]` (`:1321`)
    - `verify_public_bundle(bundle: Dict[str, Any]) -> bool` (`:1514`)
    - `initiate_handshake(peer_bundle: Dict[str, Any]) -> Tuple[Dict[str, Any], bytes]` (`:1701`)
    - `respond_to_handshake(handshake_msg: Dict[str, Any], peer_bundle: Dict[str, Any]) -> Tuple[Dict[str, Any], bytes]` (`:2091`)
  - `MLKEM` (`:161`): Wrapper for ML-KEM-1024 keygen, encaps, and decaps.
  - `MLDSA_SLHDSA_HybridSignature` (`:232`): Generates and verifies composite signatures (ML-DSA-87 + SLH-DSA-256f).
  - `QuantumResistanceModule` (`:315`): Derives hybrid master secrets via HKDF-SHA384.

### 2.3. `double_ratchet.py`
- **Classes:**
  - `DoubleRatchet` (`:1748`): Full ratchet engine combining Diffie-Hellman/KEM steps with symmetric chain ratchets.
    - `encrypt(plaintext: bytes, ad: bytes = b"") -> Tuple[MessageHeader, bytes]` (`:2547`)
    - `decrypt(header: MessageHeader, ciphertext: bytes, ad: bytes = b"") -> bytes` (`:2649`)
    - `spqr_refresh_due() -> bool` (`:3076`): Checks if an SPQR post-quantum KEM step is due.
    - `force_spqr_refresh() -> bool` (`:3125`): Immediately triggers an SPQR refresh step.
  - `MessageHeader` (`:1631`): Dataclass encapsulating `dh_pub`, `pn`, `n`, `timestamp`, `signature`.
  - `AntiReplayMechanisms` (`:3972`): Sliding window filter tracking message sequence numbers and timestamps.

### 2.4. `forward_secrecy_manager.py`
- **Classes:**
  - `ForwardSecrecyManager` (`:75`): Monitors session metrics to trigger key rotation.
  - `RotationTrigger(Enum)` (`:25`): Triggers include `MESSAGE_COUNT`, `TIME_ELAPSED`, `DECRYPT_FAILURE_THRESHOLD`.
  - `RotationConfig` (`:45`): Dataclass defining rotation parameters (default: 1000 messages, 3600 seconds, 5 decrypt failures).

### 2.5. `triple_hybrid_kem.py`
- **Classes:**
  - `TripleHybridKEM` (`:500`): Combiner orchestrating multiple KEMs.
    - `encapsulate(peer_pk: TripleHybridKeyPair) -> Tuple[TripleHybridCiphertext, bytes]` (`:960`)
    - `decapsulate(ct: TripleHybridCiphertext, sk: TripleHybridKeyPair) -> bytes` (`:1040`)
  - `KEMProfileMode(Enum)` (`:93`): Modes: `CNSA_STRICT`, `MAX_DIVERSITY`, `LEGACY_TRIPLE`.

### 2.6. Multi-Party and TreeKEM Files
- **`group_key_manager.py`:**
  - `GroupKeyManager` (`:210`): Multi-member epoch key management and group rekeying.
- **`[ISOLATED]_group_ratchet.py`:**
  - `[ISOLATED]GroupRatchet` (`:38`): Sender-key ratchet protocol for group channels.
- **`treekem.py` & `pq_treekem.py`:**
  - `RatchetTree` (`:85`): Binary tree indexing and path copath resolution.
  - `PQTreeKEM` (`:120`): Post-quantum TreeKEM using ML-KEM-1024 nodes and update paths.
- **`mls_framing.py`:**
  - `KeyPackage` (`:42`), `Proposal` (`:95`), `Commit` (`:160`): Structures RFC 9420 MLS framing containers.

---

## 3. Data Formats & Byte Layouts

### 3.1. `noise_pq.py` Wire Handshake Layouts
1. **Message 1 (Initiator $	o$ Responder):**
   - Pattern: `-> e, ekem`
   - Field 1 (`e`): Ephemeral NIST P-384 ECDH public key.
     - Compressed format: 49 bytes (`0x02` or `0x03` + 48 bytes X).
     - Uncompressed format: 97 bytes (`0x04` + 48 bytes X + 48 bytes Y).
   - Field 2 (`ekem`): Ephemeral ML-KEM-1024 public encapsulation key = 1568 bytes.
   - **Arithmetic Sum:**
     $$	ext{Total Message 1 Size (Compressed)} = 49 + 1568 = 1617	ext{ bytes}$$
     $$	ext{Total Message 1 Size (Uncompressed)} = 97 + 1568 = 1665	ext{ bytes}$$

2. **Message 2 (Responder $	o$ Initiator):**
   - Pattern: `<- e, ekem, ee, s, es`
   - Field 1 (`e`): Ephemeral NIST P-384 ECDH public key (49 or 97 bytes).
   - Field 2 (`ekem`): ML-KEM-1024 ciphertext = 1568 bytes.
   - Field 3 (`s` encrypted): Static ML-DSA-87 public key (2592 bytes) + AES-256-GCM authentication tag (16 bytes) = 2608 bytes.
   - Field 4 (`es` encrypted): ML-DSA-87 digital signature over transcript (4627 bytes) + AES-256-GCM tag (16 bytes) = 4643 bytes.
   - **Arithmetic Sum:**
     $$	ext{Total Message 2 Size (Compressed)} = 49 + 1568 + 2608 + 4643 = 8868	ext{ bytes}$$
     $$	ext{Total Message 2 Size (Uncompressed)} = 97 + 1568 + 2608 + 4643 = 8916	ext{ bytes}$$

3. **Message 3 (Initiator $	o$ Responder):**
   - Pattern: `-> s, se`
   - Field 1 (`s` encrypted): Static ML-DSA-87 public key (2592 bytes) + AES-256-GCM tag (16 bytes) = 2608 bytes.
   - Field 2 (`se` encrypted): ML-DSA-87 digital signature over transcript (4627 bytes) + AES-256-GCM tag (16 bytes) = 4643 bytes.
   - **Arithmetic Sum:**
     $$	ext{Total Message 3 Size} = 2608 + 4643 = 7251	ext{ bytes}$$

4. **Total Handshake Exchange Sum:**
   $$	ext{Total Handshake Overhead (Compressed)} = 1617 + 8868 + 7251 = 17736	ext{ bytes}$$
   $$	ext{Total Handshake Overhead (Uncompressed)} = 1665 + 8916 + 7251 = 17832	ext{ bytes}$$

### 3.2. `triple_hybrid_kem.py` Ciphertext Sums
1. **Profile `CNSA_STRICT`:**
   - Classic McEliece-8192128f Ciphertext: 208 bytes
   - ML-KEM-1024 Ciphertext: 1568 bytes
   - **Sum:** $208 + 1568 = 1776	ext{ bytes}$

2. **Profile `MAX_DIVERSITY`:**
   - Classic McEliece-8192128f Ciphertext: 208 bytes
   - ML-KEM-1024 Ciphertext: 1568 bytes
   - FrodoKEM-1344 Ciphertext: 21632 bytes
   - **Sum:** $208 + 1568 + 21632 = 23408	ext{ bytes}$

3. **Profile `LEGACY_TRIPLE`:**
   - Classic McEliece-8192128f Ciphertext: 208 bytes
   - ML-KEM-1024 Ciphertext: 1568 bytes
   - EC-P521 Ciphertext / Ephemeral PK: 133 bytes
   - **Sum:** $208 + 1568 + 133 = 1909	ext{ bytes}$

### 3.3. `double_ratchet.py` Wire Header Structure
- Encodes a binary or JSON dictionary:
  - `dh_pub`: Hex string or raw bytes of current ratchet public key (P-384: 49/97 bytes; or KEM public key).
  - `pn`: Integer previous chain length (4 bytes).
  - `n`: Integer message sequence number (4 bytes).
  - `ts`: Float timestamp (8 bytes).
  - `sig`: ML-DSA-87 signature (4627 bytes) or hybrid signature.

---

## 4. Algorithms & Pinned Libraries

1. **ML-KEM-1024 (NIST FIPS 203):**
   - Public Key: 1568 bytes, Ciphertext: 1568 bytes, Shared Secret: 32 bytes.
   - Pinned native implementation in `oqs.dll` via `liboqs_wrapper.py`.

2. **Classic McEliece-8192128f (NIST Round 4):**
   - Public Key: 1,357,824 bytes, Ciphertext: 208 bytes, Shared Secret: 32 bytes.
   - Pinned native implementation in `oqs.dll`.

3. **FrodoKEM-1344 (NIST Round 3 Alternate):**
   - Public Key: 21,520 bytes, Ciphertext: 21,632 bytes, Shared Secret: 32 bytes.
   - Pinned native implementation in `oqs.dll`.

4. **NIST P-384 / SecP384r1 (NIST SP 800-56A):**
   - Ephemeral ECDH key agreement generating 48-byte shared secret via `cryptography.hazmat.primitives.asymmetric.ec`.

5. **ML-DSA-87 (NIST FIPS 204):**
   - Public Key: 2592 bytes, Signature: 4627 bytes.

6. **Key Derivation & Hashing:**
   - HKDF-SHA384 (RFC 5869) and HMAC-SHA384 for symmetric ratcheting.
   - HKDF-Expand-SHA3-512 in `pq_treekem.py:35` for epoch secret derivation.

---

## 5. Dependencies

### 5.1. External Dependencies
- `cryptography` (hazmat primitives: `hashes`, `ec`, `kdf.hkdf`, `ciphers.aead.AESGCM`): Core elliptic-curve and symmetric encryption operations.
- `liboqs` (`oqs.dll` v0.16.0): Native shared library providing ML-KEM-1024, Classic McEliece, FrodoKEM, and ML-DSA-87.

### 5.2. Internal Repository Dependencies
- `liboqs_wrapper.py`: Thin ctypes wrapper providing `LibOQS_KEM` and `LibOQS_SIG`.
- `pqc_algorithms.py`: Provides algorithm constants and fallback wrappers.
- `cnsa_purity.py`: Algorithmic quarantine rules.

---

## 6. Failure Behavior

1. **`noise_pq.py`:**
   - Tag Verification Discrepancy: Any failure in `AESGCM.decrypt` raises `NoiseError("bad mac")` (`:185`).
   - Signature Mismatch: Invalid static ML-DSA-87 signatures abort the handshake immediately with `NoiseError("bad signature")` (`:312, 381`).
   - State Transition Violations: Reading or writing out-of-order handshake tokens raises `NoiseError("invalid handshake state")`.

2. **`double_ratchet.py`:**
   - Message Gap Ceiling: If $header.pn - receiving\_message\_number > 1000$ (`HARD_MAX_SKIP`), logs security alert and aborts decryption fail-closed to prevent CPU denial-of-service (`:4145, 4210`).
   - Memory Scrubbing on Decryption: Ephemeral secrets (`fresh_ss`, `new_dh_output`) are zeroized in `finally` blocks via `_wipe_secret_best_effort` (`:3220-3222`).

3. **`hybrid_kex.py`:**
   - Signature Chain Authentication: In `respond_to_handshake`, the responder verifies the entire message transcript and ephemeral-key certificate before executing KEM decapsulation; invalid signatures abort before decapsulation (`:2317, 2425`).

4. **`mls_framing.py` & `pq_treekem.py`:**
   - Transcript Hash Mismatch: Commit verification fails closed if the proposed transcript hash does not chain to the previous epoch hash (`:180`).
   - Expired Key Packages: Key packages older than allowed lifetime are rejected at parse time.

---

## 7. Configuration / Environment Variables

| Variable Name | Defined In File | Default Value | Technical Purpose & Impact |
|:---|:---|:---|:---|
| `P2P_KEM_PROFILE` | `triple_hybrid_kem.py:440` | `"cnsa_strict"` | Selects KEM combiner mode: `"cnsa_strict"` (McEliece + ML-KEM), `"max_diversity"` (+ FrodoKEM), or `"legacy_triple"` (+ EC-P521). |
| `P2P_ENABLE_VULN_HQC` | `triple_hybrid_kem.py:40` | `0` | If set to `1`, enables unrecommended HQC KEM mode. |
| `P2P_SPQR_MSG_INTERVAL` | `double_ratchet.py:1875` | `50` | Number of messages sent before triggering an SPQR post-quantum KEM ratchet refresh. |
| `P2P_SPQR_MAX_AGE` | `double_ratchet.py:1883` | `604800` (7 days) | Elapsed seconds before triggering an SPQR post-quantum KEM ratchet refresh. |
| `P2P_GROUP_REQUIRE_PAIRWISE` | `group_key_manager.py:85` | `0` | If set to `1`, requires established pairwise ratchets between all group members. |
| `P2P_GROUP_REQUIRE_SIGNED_COMMITS` | `group_key_manager.py:92`, `pq_treekem.py:28` | `0` | If set to `1`, enforces ML-DSA-87 signatures on group commit messages. |
| `P2P_DPAPI_MACHINE_SCOPE` | `hybrid_kex.py:105` | `0` | If set to `1`, uses machine-wide DPAPI key scope instead of current-user scope. |
| `P2P_FAIL_ON_SOFTWARE_FALLBACK` | `hybrid_kex.py:120` | `0` | If set to `1`, aborts if hardware acceleration is unavailable. |
| `P2P_STORAGE_PASSPHRASE` | `hybrid_kex.py:115` | None | Passphrase for encrypting persisted master secrets. |
| `P2P_STRICT_SECURITY` | `hybrid_kex.py:130`, `double_ratchet.py:110` | `0` | If set to `1`, disables classical fallback and enforces pure post-quantum algorithms. |
| `P2P_ALLOW_CLASSICAL` | `double_ratchet.py:95` | `0` | If set to `1`, permits non-PQ Diffie-Hellman operations without KEM steps. |
| `P2P_DENIABLE` / `P2P_DENIABLE_MESSAGING` | `double_ratchet.py:125` | `0` | Toggles deniable authentication versus non-repudiable signatures. |

---

## 8. Tests Covered & Not Covered

### 8.1. Tests Covered (Directly Executed and Verified)
- `tests/test_noise_pq_hardened.py` (14 passed):
  - Validates `Noise_XXhfs` roundtrip, state initialization, tag verification failure, and replay protection.
- `tests/test_noise_pq_purity.py` (8 passed):
  - Validates strict CNSA 2.0 algorithmic constraints within the Noise state machine.
- `tests/test_combiner_downgrade_guard.py` (4 passed):
  - Validates combiner resistance against algorithmic downgrade attacks.
- `tests/test_ratchet_dss_mldsa87.py` (3 passed):
  - Validates ML-DSA-87 signature authentication inside the Double Ratchet wire format.
- `tests/test_[ISOLATED]_group_ratchet.py` (3 passed):
  - Validates three-party group messaging roundtrip, two-person integrity epoch advancement, and synchronization.
- `tests/test_treekem.py` (9 passed):
  - Validates leaf indexing, copath resolution, tree rotation, blank path handling, and tree hash agreement.
- `tests/test_tier4_pq_treekem_and_tfc.py` (10 passed, 1 skipped):
  - Validates 4-party update path synchronization, post-compromise continuous ratcheting, eviction fail-closed behavior, and fork detection.
- `tests/test_mls_framing.py` (11 passed):
  - Validates KeyPackage lifetime, Proposal verification, Commit transcript chaining, and tamper rejection.
- `tests/test_cnsa_max_profile.py` (3 passed):
  - Validates `TripleHybridKEM` execution under `MAX_DIVERSITY` and `CNSA_STRICT` profiles.
- `tests/test_crypto_root_fixes.py` (13 passed):
  - Validates forward secrecy triggers and rotation state tracking.

### 8.2. Not Covered / Zero Test Execution
- None. All 10 files in `ratchet_kex_protocol` have direct test coverage across the test suites.

---

## 9. Not Implemented / Stubs

1. **Deniable Authentication Ring Signatures in `double_ratchet.py:P2P_DENIABLE`:**
   - Although `P2P_DENIABLE` is recognized as an environment flag, true off-the-record deniability (e.g., designated verifier proofs or ring signatures) is not implemented for ML-DSA-87; messages fall back to explicit non-repudiable ML-DSA-87 signatures.

2. **Hardware DPAPI Machine Scope Isolation:**
   - `hybrid_kex.py:_dpapi_scope_flags` uses Windows DPAPI; on non-Windows platforms, DPAPI calls fail or fall back to file storage encrypted with `P2P_STORAGE_PASSPHRASE`.

---

## 10. Known Limitations

1. **Bandwidth Overhead of Classic McEliece:**
   - In `hybrid_kex.py` and `triple_hybrid_kem.py`, Classic McEliece-8192128f requires an encapsulation key of 1,357,824 bytes (~1.36 MB). Exchanging this public key introduces significant network latency and packet fragmentation on constrained links.

2. **Out-of-Order Message Memory Bounds:**
   - While `HARD_MAX_SKIP = 1000` bounds single-chain message skipping, storing up to 2000 skipped keys (`MAX_SKIPPED_TOTAL`) consumes RAM and requires periodic time-based eviction to prevent memory accumulation in long-lived sessions.

3. **Multi-Party Group Scalability:**
   - `[ISOLATED]GroupRatchet` uses an $O(N)$ sender-key distribution scheme, where each member must distribute an encrypted sender key to all peers. In large groups ($N > 100$), `pq_treekem.py` ($O(\log N)$) is required to avoid quadratic key distribution overhead.

---

## 11. Discrepancies

1. **Promotional Banners in File Headers:**
   - `triple_hybrid_kem.py:3` and `double_ratchet.py:3` contain promotional banners and non-technical adjectives (flagged for cataloging in `docs/audit/discrepancies.md`).

2. **Handshake Architecture Redundancy:**
   - The repository maintains two separate post-quantum handshake protocols: `noise_pq.py` (`Noise_XXhfs`) and `hybrid_kex.py` (custom X3DH hybrid). Documentation in `docs/ARCHITECTURE.md` references `noise_pq.py` as the primary transport protocol, while `secure_p2p.py` references `hybrid_kex.py`.

3. **Discrepancy in Double Ratchet Lines Count in Documentation:**
   - `docs/modules/double_ratchet.md:1` lists `double_ratchet.py` as `~4100 lines`, whereas the verified line count is 5,709 lines.

---

## 12. Open Questions

1. **Handshake Unification Strategy:**
   - Is `Noise_XXhfs` (`noise_pq.py`) planned to replace the custom hybrid handshake in `hybrid_kex.py`, or are both intended to coexist indefinitely?
2. **Standardization of SPQR Cadence:**
   - Is the SPQR 50-message / 7-day interval aligned with an external interoperability specification, or is it an empirical threshold derived from the Apple PQ3 / Signal research papers?
3. **Group Ratchet Convergence:**
   - Will future releases deprecate the flat sender-key approach (`[ISOLATED]_group_ratchet.py`) in favor of TreeKEM (`pq_treekem.py`) as the singular group key distribution protocol?

---
<!-- Destroyer-ST2027 Military Production Hardening Release (2026-10-26) -->
<!-- NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204 -->
