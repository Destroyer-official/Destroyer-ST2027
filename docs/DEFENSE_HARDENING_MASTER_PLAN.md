# Sovereign Transmit 2027 (ST2027) — Defense Hardening Master Plan
## Detailed Step-by-Step Implementation & Verification Blueprint

**Target Objective:** Resolve 100% of external auditor findings, eliminate every exploit surface, and elevate ST2027 to a genuine 10/10 across Algorithm Choice, Protocol Design, Implementation Correctness, Verification Evidence, Honesty of Claims, and Usability.

---

## Roadmap Overview

```
+========================================================================================================+
| PHASE 1: CRYPTOGRAPHIC CORRECTNESS & ANTI-EXPLOIT CORE                                                 |
|   ├── Task 1.1: Replay Window Decoupling in secure_transmit_2027.py                                    |
|   ├── Task 1.2: Native Replay Window Decoupling in ts_rt and ts_runtime.py                            |
|   ├── Task 1.3: Nonce Reuse Elimination & Persistent Monotonic State in rust_data_plane               |
|   └── Task 1.4: Active Exploit Regression Battery (Replay DoS & Nonce Collisions)                      |
+--------------------------------------------------------------------------------------------------------+
| PHASE 2: PROTOCOL TRUTH & HANDSHAKE ALIGNMENT                                                          |
|   ├── Task 2.1: Handshake Unification (secure_transmit_2027.py vs noise_pq.py)                         |
|   ├── Task 2.2: Initiator Identity Exposure Resolution (Wire Encryption vs Selective Disclosure)        |
|   └── Task 2.3: Continuous Post-Compromise Security (PCS) Ratchet vs Re-handshake Doctrine              |
+--------------------------------------------------------------------------------------------------------+
| PHASE 3: PLATFORM GATES & SUPPLY CHAIN CRYPTOGRAPHIC ENFORCEMENT                                       |
|   ├── Task 3.1: Cryptographically Signed AO Waivers with ML-DSA-87 Root Anchor                         |
|   ├── Task 3.2: Signed seL4 Microkernel & CMVP Attestation Records                                     |
|   ├── Task 3.3: OpenSSL FIPS Provider Cryptographic Context Enforcement                                |
|   ├── Task 3.4: Fail-Closed DLL Supply Chain Loading (Eliminate Warning-Only Fallbacks)                |
|   └── Task 3.5: Embedded Pinned Root Keys (Eliminate Working Directory .pub Dependencies)              |
+--------------------------------------------------------------------------------------------------------+
| PHASE 4: TRUTH IN DEFENSE CLAIMS & FORMAL VERIFICATION ALIGNMENT                                       |
|   ├── Task 4.1: Unaccredited Badge Purge & Realistic Defense Baseline Declaration                      |
|   ├── Task 4.2: Exact Formal Verification Attribution (5 Kani Proofs + 24 Invariant Properties)        |
|   ├── Task 4.3: Physical Boundary Disclosures (Python Memory Wiping & Traffic Analysis Limits)         |
|   └── Task 4.4: Hardware Test Mock Audit & Live Probe Decoupling                                       |
+--------------------------------------------------------------------------------------------------------+
| PHASE 5: ATTACK SURFACE REDUCTION & ARCHITECTURAL UNIFORMITY                                           |
|   ├── Task 5.1: Native Data-Plane Cipher Uniformity (AES-256-GCM CNSA 2.0 Alignment)                   |
|   ├── Task 5.2: Attack Surface Purge (Quarantine Sprawling Prototype Files)                             |
|   └── Task 5.3: Unified Operator CLI & Automated Self-Test Harness                                     |
+========================================================================================================+
```

---

# Phase 1: Cryptographic Correctness & Anti-Exploit Core

### Task 1.1: Decouple Replay Check from Window Mutation in `secure_transmit_2027.py`

#### 1. Vulnerability Analysis
- **File:** [`secure_transmit_2027.py:553-640`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/secure_transmit_2027.py#L553-L640)
- **Mechanics of Flaw:** In `Channel.open(wire)`, `self.recv_win.check_and_mark(seq)` is invoked at line 633. The AEAD authentication tag is verified at line 636 via `AESGCM.decrypt()`. When an unauthenticated attacker transmits a forged packet with sequence number $S = 2^{64}-1$ and an arbitrary payload:
  1. `check_and_mark` shifts `self.base` to $2^{64}-64$ and sets the MSB in `self.bitmap`.
  2. `AESGCM.decrypt` raises `SecurityError("authentication failed")`.
  3. The packet is dropped, but the replay window remains shifted.
  4. The next legitimate message arrives with valid sequence $S_{\text{valid}} \approx 1$.
  5. `check_and_mark` sees $S_{\text{valid}} < \text{self.base}$, rejecting it as an ancient replay.
  6. **Impact:** Permanent Denial of Service (DoS) from a single unauthenticated forged packet.

#### 2. Governing Technical Specification
- **RFC 6479:** *4-Byte Sequence Numbers for IPsec ESP and AH (Sliding Replay Window)*.
- **WireGuard Protocol Specification (§5.4.4):** Sequence numbers MUST be checked in a read-only manner prior to cryptographic verification, and the window bitmap MUST NOT be updated until the authentication tag has been fully verified.

#### 3. Step-by-Step Implementation Guide
1. Open [`secure_transmit_2027.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/secure_transmit_2027.py).
2. Locate `class ReplayWindow` (lines 553–583).
3. Replace `check_and_mark(self, seq: int)` with two discrete methods:
   - `check(self, seq: int) -> None`:
     - Validate bounds: $0 \le \text{seq} < 2^{64}$.
     - If not started: return (valid initial sequence).
     - If $\text{seq} < \text{self.base}$: raise `SecurityError("replay rejected")`.
     - Compute offset: $\text{off} = \text{seq} - \text{self.base}$.
     - If $\text{off} < \text{REPLAY\_WINDOW}$ and $(\text{self.bitmap} \gg \text{off}) \ \& \ 1$: raise `SecurityError("replay rejected")`.
     - DO NOT mutate `self.base` or `self.bitmap`.
   - `mark(self, seq: int) -> None`:
     - If not started: set `self.base = seq`, `self.bitmap = 1`, `self.started = True`, return.
     - If $\text{seq} < \text{self.base}$: return (already validated by check).
     - Compute offset: $\text{off} = \text{seq} - \text{self.base}$.
     - If $\text{off} < \text{REPLAY\_WINDOW}$: set `self.bitmap |= (1 << off)`.
     - Else: slide window by $\text{shift} = \text{off} - (\text{REPLAY\_WINDOW} - 1)$. If $\text{shift} \ge \text{REPLAY\_WINDOW}$, `self.bitmap = 0`, else `self.bitmap >>= shift`. Update `self.base += shift`, set MSB in bitmap.
4. Locate `Channel.open(self, wire: bytes)` (lines 621–640).
5. Modify execution sequence:
   ```python
   # Step 1: Read-only check
   self.recv_win.check(seq)
   aad = wire[:12]
   
   # Step 2: Authenticate and Decrypt
   try:
       pt = AESGCM(self.state.key()).decrypt(
           self._nonce(seq, self.direction_in), wire[12:], aad)
   except Exception:
       raise SecurityError("authentication failed")
       
   # Step 3: Mutate window ONLY on success
   self.recv_win.mark(seq)
   ```

#### 4. Verification Gate
- Write test in `test_secure_transmit_2027.py`:
  ```python
  def test_forged_packet_does_not_poison_replay_window(tmp_path):
      cli_kp, srv_kp = _kp_pair("poison", tmp_path)
      # Establish channel
      # 1. Send legitimate frame seq=1 -> verified
      # 2. Inject forged frame seq=(1<<64)-1 with invalid tag -> fails auth
      # 3. Send legitimate frame seq=2 -> MUST SUCCEED (not dropped as replay)
  ```
- **Acceptance Criteria:** Legitimate frame `seq=2` decrypts cleanly; 0 frames dropped after attacker probe.

---

### Task 1.2: Decouple Native Rust Replay Window in `ts_rt` and `ts_runtime.py`

#### 1. Vulnerability Analysis
- **File:** [`ts_rt/src/lib.rs`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_rt/src/lib.rs), [`ts_runtime.py:240-260`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_runtime.py#L240-L260)
- **Mechanics of Flaw:** `tsrt_replay_check_mark` combines check and mark in a single native invocation. Any C FFI caller is forced to advance the native window prematurely if verifying framing before AEAD.

#### 2. Step-by-Step Implementation Guide
1. In `ts_rt/src/lib.rs`, split the C API:
   - `pub extern "C" fn tsrt_replay_check(handle: *mut ReplayWindow, seq: u64) -> i32`
   - `pub extern "C" fn tsrt_replay_mark(handle: *mut ReplayWindow, seq: u64) -> i32`
   - Retain `tsrt_replay_check_mark` for backward compatibility.
2. In `ts_runtime.py`:
   - Bind `tsrt_replay_check` and `tsrt_replay_mark` via ctypes.
   - Update `NativeReplayWindow` with `.check(seq)` and `.mark(seq)`.

#### 3. Verification Gate
- Unit test in `test_ts_runtime.py` verifying calling `.check(99999)` returns 1 (valid), but calling `.check(5000)` afterwards still returns 1 until `.mark(99999)` is explicitly invoked.

---

### Task 1.3: Eliminate Nonce Reuse in `rust_data_plane` (`secure-transmit`)

#### 1. Vulnerability Analysis
- **File:** [`rust_data_plane/src/main.rs:105-140`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/rust_data_plane/src/main.rs#L105-L140)
- **Mechanics of Flaw:**
  1. The CLI takes `--seq` optional flag defaulting to `1` on every run.
  2. The key is provided as static hex on the command line: `--key <hex>`.
  3. Running `secure-transmit send` twice with the same key uses `seq = 1` for both ciphertexts under ChaCha20-Poly1305.
  4. Nonce reuse in stream ciphers ($C_1 \oplus C_2 = P_1 \oplus P_2$) leaks cleartext XOR differences and exposes the Poly1305 internal key, completely destroying confidentiality and authenticity.
  5. The CLI command line leaks the raw key in plain text to the host process tree (`Get-Process`, `ps aux`).

#### 2. Governing Technical Specification
- **NIST SP 800-38D (§8):** Uniqueness Requirement on Nonces. Nonces must never be repeated under the same key across any invocation.
- **DoD Zero Trust Guidance:** Secrets must never be exposed via process command-line arguments.

#### 3. Step-by-Step Implementation Guide
1. Open `rust_data_plane/src/main.rs`.
2. **Remove `--seq` argument:** Delete the user-controlled `--seq` parameter completely. The sequence number MUST NOT be arbitrary user input.
3. **Remove `--key <hex>` argument:**
   - Replace with `--key-file <PATH>` and `--key-stdin`.
   - Read key bytes into locked/zeroized memory buffer, zeroizing immediately upon parsing.
4. **Implement Persistent Monotonic Session State File (`--state <PATH>`):**
   - Define `SessionState` struct:
     ```rust
     #[derive(Serialize, Deserialize)]
     struct SessionState {
         key_id: [u8; 16],
         send_seq: u64,
         recv_win_base: u64,
         recv_win_bitmap: u64,
     }
     ```
   - On `send`:
     - Open state file with exclusive OS file lock (`fs2` or platform advisory lock).
     - Read current `send_seq`.
     - Increment `send_seq += 1` (fail closed on $2^{64}-1$).
     - Atomic write/sync state file to disk before emitting datagram.
   - On `recv`:
     - Open state file with exclusive lock.
     - Validate incoming frame against `AntiReplayWindow::check()`.
     - Authenticate AEAD tag.
     - On success: `AntiReplayWindow::mark()`, write updated state atomically.

#### 4. Verification Gate
- Test in `test_rust_standalone_binary.py`:
  1. Initialize session state file.
  2. Execute `send` command twice.
  3. Inspect emitted packets on loopback: verify sequence numbers are strictly monotonic ($N$, $N+1$).
  4. Verify no execution path allows duplicate sequence numbers.

---

### Task 1.4: Active Exploit Regression Battery

#### 1. Scope
Create a dedicated test file: [`test_exploit_regressions.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/test_exploit_regressions.py) that directly incorporates the external reviewer's test scripts as permanent automated defenses:
1. **Exploit 1: Replay Window Poisoning DoS:**
   - Transmit valid frame $F_1$ (`seq=1`).
   - Transmit forged frame $F_{\text{attack}}$ (`seq=2**64 - 1`, invalid MAC).
   - Assert $F_{\text{attack}}$ raises `SecurityError("authentication failed")`.
   - Transmit valid frame $F_2$ (`seq=2`).
   - Assert $F_2$ succeeds and decrypts properly.
2. **Exploit 2: Nonce Collision Detection:**
   - Execute two CLI send operations.
   - Capture nonces used in framing.
   - Assert $\text{Nonce}_1 \ne \text{Nonce}_2$.

---

# Phase 2: Protocol Truth & Handshake Alignment

### Task 2.1: Handshake Unification (`secure_transmit_2027.py` vs `noise_pq.py`)

#### 1. Problem Analysis
- `README.md` describes `Noise_XXhfs` in `noise_pq.py`.
- However, `secure_transmit_2027.py` implements its own custom 2-message exchange (`build_client_hello`, `server_accept`, `client_finish`) and never imports `noise_pq.py`.

#### 2. Engineering Solution
- **Action:** Integrate `noise_pq.py` as the authoritative handshake engine in `secure_transmit_2027.py`:
  1. In `secure_transmit_2027.py`, import `Noise_XXhfs_Handshake` from `noise_pq.py`.
  2. Execute the 3-message `Noise_XXhfs` handshake state machine:
     - Message 1 ($A \to B$): $e$ (ephemeral P-384 + ML-KEM-1024 public keys)
     - Message 2 ($B \to A$): $e, ee, s, es$ (encrypted responder static public key and signatures)
     - Message 3 ($A \to B$): $s, se$ (encrypted initiator static public key and signatures)
  3. Derive session keys from `Noise_XXhfs` split keys ($K_1, K_2$).

---

### Task 2.2: Initiator Identity Exposure Resolution

#### 1. Problem Analysis
- In the current `build_client_hello` in `secure_transmit_2027.py:377-380`, the initiator transmits `sig_pk` (its long-term identity public key) unencrypted in Message 1.
- This invalidates the claim of "Identity Hiding" against passive network adversaries.

#### 2. Engineering Solution
- Under the unified `Noise_XXhfs` handshake (Task 2.1), the initiator's static public key $s$ is transmitted in **Message 3**, encrypted under the cipher key established by the ephemeral DH and KEM combinations ($e, ee$).
- **Result:** Passive network observers see only high-entropy ephemeral public keys; identities are 100% hidden.

---

### Task 2.3: Continuous Post-Compromise Security (PCS) Ratchet

#### 1. Problem Analysis
- The reviewer noted: *"The model shows a fresh re-handshake gives a key independent of the old one... That is useful, but it is not Signal-style post-compromise security."*
- Periodic re-handshaking (every 1 MiB or 15 minutes) is discrete session replacement, not a continuous per-message post-quantum ratchet.

#### 2. Engineering Solution
- Clearly differentiate and document the architecture:
  1. **Primary Tactical Channel:** Operates an epoch-based KEM ratchet (continuous hybrid ratcheting where every $N$ messages or idle intervals, a new ephemeral ML-KEM-1024 key encapsulation is interleaved into the symmetric chain).
  2. Update documentation to cite: *"Continuous Epoch Ratchet (CER) with hybrid ML-KEM-1024 / P-384 interleaving"*, explicitly noting the epoch frequency.

---

# Phase 3: Platform Gates & Supply Chain Cryptographic Enforcement

### Task 3.1: Cryptographically Sign AO Waivers with ML-DSA-87 Root Anchor

#### 1. Vulnerability Analysis
- In `ts_runtime.py:467-485`, `load_waiver()` accepts plain unsigned JSON. Anyone with file write access can bypass platform requirements.

#### 2. Step-by-Step Implementation Guide
1. Open [`ts_runtime.py`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/ts_runtime.py).
2. Modify `load_waiver(path: Path) -> Dict[str, Any]`:
   - Require structured envelope containing `payload` and `signature`.
   - Extract canonical JSON representation of `payload` (sorted keys, no whitespace).
   - Verify `signature` against the Root CA public key using `LibOQS_MLDSA_87().verify()`.
   - If verification fails or signature is absent: raise `TSRequiredError("AO waiver signature invalid or unverified")`.
3. Create a helper utility in `scripts/sign_waiver.py` to allow authorized personnel to generate signed waivers using the offline Root CA key.

---

### Task 3.2: Sign seL4 Microkernel & CMVP Attestation Records

#### 1. Vulnerability Analysis
- `P2P_SEL4_RECORD` and CMVP provider JSON files are operator-written files with no cryptographic provenance.

#### 2. Step-by-Step Implementation Guide
1. In `ts_runtime.py:load_sel4_record()`:
   - Require attached `.sig` file for the record.
   - Verify digital signature against a pinned platform public key before trusting the microkernel configuration.
2. In `ts_hw_layer.py:verify_fips_provider()`:
   - Verify that the loaded OpenSSL provider actively reports `"fips=yes"` directly from the C API (`OSSL_PROVIDER_available(NULL, "fips")`), rather than merely reading an operator's JSON assertion.

---

### Task 3.3: Fail-Closed DLL Supply Chain Loading

#### 1. Vulnerability Analysis
- In `liboqs_wrapper.py:198-204`, if `dependency_security_verifier` is missing or fails to import, the code prints a warning and loads `oqs.dll` anyway.
- The `.pub` and `.sig` sidecars sit in the working directory next to the `.dll`, making substitution trivial.

#### 2. Step-by-Step Implementation Guide
1. In `liboqs_wrapper.py`:
   - Delete `try ... except ImportError` around dependency verification.
   - Make import strictly mandatory:
     ```python
     from dependency_security_verifier import verify_critical_dependency, DependencySecurityError
     ```
   - If import fails, raise a fatal `ImportError` immediately.
2. In `dependency_security_verifier.py`:
   - Embed the hardcoded Ed25519 public key and SHA-384 expected hash directly in Python code constants (`EMBEDDED_OQS_HASH`, `EMBEDDED_OQS_PUBKEY`).
   - Disallow reading `.pub` files from the local directory.
   - If the DLL hash or signature does not match the embedded constant, abort execution fail-closed.

---

# Phase 4: Truth in Defense Claims & Formal Verification Alignment

### Task 4.1: Purge Unearned Accreditation Badges from `README.md`

#### 1. Implementation Guide
1. Open [`README.md`](file:///d:/code/Main_projects/p2p/p2p_6_1-26/README.md).
2. Remove:
   - `Common Criteria EAL4+` badge
   - `FIPS 140-3 Level 3/4` badge
   - `DoD Zero Trust Level 4` badge
3. Replace with honest engineering baseline indicators:
   - `Posture: NSA CNSA Suite 2.0 Engineering Baseline`
   - `Formal Proof: ProVerif 2.05 Verified Symbolic Model`
   - `Model Checking: Kani CBMC Verified (5 Proofs + 24 Property Tests)`
   - `Evaluation Status: Pre-Evaluation Prototype / Research Baseline`
4. In Section 2, state clearly: *"This software is an engineering baseline designed to meet the technical specifications of CNSA 2.0. It has not undergone accredited laboratory evaluation (FIPS 140-3 CMVP / Common Criteria) and does not possess a government Authority to Operate (ATO)."*

---

### Task 4.2: Accurate Characterization of Formal Verification Proofs

#### 1. Implementation Guide
1. In `README.md` and `docs/formal/README.md`, update all references:
   - State accurately: *"5 machine-checked formal proofs under Kani bounded model checking; 24 automated property-based invariant test suites."*
   - List the exact 5 functions verified by Kani:
     1. `kani_harness::property_doubles::nonce_domain_separation`
     2. `kani_harness::property_doubles::replay_window_monotonic_and_drops`
     3. `kani_harness::property_doubles::ct_eq_and_select_no_secret_branch`
     4. `kani_harness::nostd_microcore::test_stack_secret_zeroize_on_drop`
     5. `kani_harness::property_doubles::max_stream_bytes_cap_enforced`

---

### Task 4.3: Physical Boundary & Memory Disclosures

#### 1. Implementation Guide
1. In `README.md` and `SYSTEM_SECURITY_DOCUMENTATION.md`, add honest disclosures:
   - **Memory Hygiene:** *"Python immutable `bytes` objects cannot be wiped deterministically due to runtime garbage collector copies. High-assurance operational deployments must execute via the standalone native Rust data-plane (`secure-transmit`)."*
   - **Traffic Analysis:** *"Constant-rate traffic shaping (50ms interval) provides statistical masking against localized ISP/packet sniffers. It does not provide mathematical security against a global passive adversary with full autonomous network vantage points."*

---

# Phase 5: Attack Surface Reduction & Cryptographic Uniformity

### Task 5.1: Native Data-Plane Cipher Uniformity (AES-256-GCM Alignment)

#### 1. Implementation Guide
1. In `rust_data_plane/Cargo.toml`:
   - Add `aes-gcm = { version = "0.10", default-features = false, features = ["aes"] }`.
2. In `rust_data_plane/src/aead.rs`:
   - Replace ChaCha20-Poly1305 with AES-256-GCM.
   - Ensure native frames and Python frames share identical wire format and cipher primitives.
3. This eliminates the contradiction between "Pure CNSA 2.0" and the use of ChaCha20.

---

### Task 5.2: Attack Surface Purge (Quarantine Sprawling Files)

#### 1. Implementation Guide
1. Move non-core, experimental, or unreviewed modules to `archive/`:
   - Move `nc3_nuclear_command.py`, `zk_authenticator.py`, `allied_gateway.py` to `archive/experimental/`.
2. Retain only the lean, audited production core:
   - `secure_transmit_2027.py`, `noise_pq.py`, `trust_anchor.py`, `cnsa_purity.py`, `crypto_selftest.py`, `transport_anonymity.py`, `spo_dpo.py`, `ts_hw_layer.py`, `ts_runtime.py`, `ts_attest.py`
   - `rust_data_plane/` and `ts_rt/`
   - Active test suites and deployment runbooks

---

## Verification & Tracking Dashboard

| Task # | Task Description | Target File | Status | Gate Check |
|---|---|---|---|---|
| **1.1** | Replay Window Decoupling | `secure_transmit_2027.py` | `[ ] PENDING` | `test_exploit_regressions.py::test_replay_poison_prevented` |
| **1.2** | Native Rust Replay Decoupling | `ts_rt/src/lib.rs` | `[ ] PENDING` | `test_ts_runtime.py::test_native_replay_check_separate` |
| **1.3** | Rust CLI Nonce Reuse Elimination | `rust_data_plane/src/main.rs` | `[ ] PENDING` | `test_rust_standalone_binary.py::test_monotonic_state` |
| **1.4** | Active Exploit Regression Suite | `test_exploit_regressions.py` | `[ ] PENDING` | Both exploit tests passing 100% |
| **2.1** | Handshake Unification | `secure_transmit_2027.py` | `[ ] PENDING` | End-to-end loopback transfer with Noise_XXhfs |
| **2.2** | Initiator Identity Encryption | `secure_transmit_2027.py` | `[ ] PENDING` | Wire capture asserts zero cleartext `sig_pk` in msg 1 |
| **2.3** | Epoch Ratchet Specification | `docs/ARCHITECTURE.md` | `[ ] PENDING` | Documentation audit |
| **3.1** | Cryptographically Signed AO Waivers | `ts_runtime.py` | `[ ] PENDING` | `test_ts_runtime.py::test_unsigned_waiver_fails_closed` |
| **3.2** | Signed Attestation Records | `ts_runtime.py`, `ts_hw_layer.py` | `[ ] PENDING` | `test_ts_hw_layer.py::test_unsigned_cmvp_fails_closed` |
| **3.3** | OpenSSL FIPS C API Enforcement | `ts_hw_layer.py` | `[ ] PENDING` | `test_ts_hw_layer.py::test_fips_provider_c_api` |
| **3.4** | Fail-Closed DLL Loading | `liboqs_wrapper.py` | `[ ] PENDING` | `test_secure_transmit_2027.py::test_missing_verifier_aborts` |
| **3.5** | Embedded Root Public Keys | `dependency_security_verifier.py` | `[ ] PENDING` | Zero `.pub` files read from disk at runtime |
| **4.1** | Accreditation Badge Purge | `README.md` | `[ ] PENDING` | Zero false certification claims in markdown |
| **4.2** | Formal Proof Count Alignment | `README.md`, `docs/formal/` | `[ ] PENDING` | Exact 5 Kani proofs and 24 property tests cited |
| **4.3** | Physical Boundary Disclosures | `README.md` | `[ ] PENDING` | Memory wiping & traffic analysis disclosures verified |
| **4.4** | Mock Audit & Test Independence | `test_ts_hw_layer.py` | `[ ] PENDING` | Real failure paths tested without simulated bypasses |
| **5.1** | Rust AES-256-GCM Alignment | `rust_data_plane/src/aead.rs` | `[ ] PENDING` | Zero ChaCha20 dependencies in native data-plane |
| **5.2** | Attack Surface Sprawl Purge | Project root | `[ ] PENDING` | Core production surface < 15 files |
| **5.3** | Unified Operator CLI Harness | `secure_transmit_2027.py` | `[ ] PENDING` | Single-command deployment and self-test verified |
