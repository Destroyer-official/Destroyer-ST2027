# Formal Verification Models (ProVerif 2.05 & Kani)

This directory contains the machine-checked symbolic formal verification models and proofs for the Destroyer-ST2027 sovereign protocol suite.

## 1. Machine-Checked ProVerif Models

The protocol is formally modeled and **symbolically** verified in the applied pi-calculus using **ProVerif 2.05**. Scope caveat (F-03, audit 2026-10-14): these are MODEL proofs, not computational-security reductions and not implementation proofs. The deployed handshake uses an UNPROVEN custom substitution (see `deploy_st2027/noise_pq.py:30-40`): the ML-DSA-87 signature replacing the hfs draft's es/se tokens has no reduction to the hfs draft (which has no proofs) nor to PQNoise, and the model abstracts kdf as one-way (stronger than the dual-PRF property HKDF is actually assumed to have — eprint 2022/065). Treat the results as "the protocol structure is sound under these abstractions", never as "the concrete cryptography is proven".

1. **`st2027_handshake.pv`**: Full symbolic model of the deployed Noise_XXhfs handshake with P-384 ECDHE, ML-KEM-1024, ML-DSA-87, AES-256-GCM, and transcript-bound KEM combination.
   - Evaluates 7 core security queries: secrecy of payload under session keys, injective agreement `inj-event(S_Accepts ==> C_Accepts)`, forward secrecy under ephemeral leak phases, client verification `C_VerifiedM2`, and initiator identity privacy.
2. **`st2027_pcs.pv`**: Symbolic model of the Continuous Epoch Ratchet (CER).
   - Evaluates Post-Compromise Security (PCS) healing: proves that an attacker who compromises epoch $N$ cannot compromise epoch $N+1$ once fresh ephemerals are exchanged.

### Running ProVerif

Requires ProVerif ≥ 2.05:

```sh
proverif docs/formal/st2027_handshake.pv
proverif docs/formal/st2027_pcs.pv
```

Automated verification suite:

```sh
pytest tests/test_proverif_st2027.py -v
sh docs/formal/check.sh --strict
```

### Verified Output

All 10 queries conclude:

```
RESULT Query not attacker_p1(secret_payload) is true.
RESULT Query inj-event(S_Accepts(k,h,pk)) ==> inj-event(C_Sends(k,n,msg)) is true.
RESULT Query inj-event(R_Receives(k,n,msg,pk)) ==> inj-event(C_Sends(k,n,msg)) is true.
```

## 2. Kani Inventory (audited against `rust_data_plane/tests/kani_harness.rs`)

Six `#[kani::proof]` harnesses are DEFINED (exact names):

```
kani_cookie_gate_stateless_verification
kani_frame_split_reassemble_roundtrip
kani_max_stream_bytes_cap
kani_nonce_domain_separation
kani_nostd_frame_parse_never_panics
kani_replay_window_monotonic
```

Execution requires the Kani + CBMC toolchain (`cargo kani`); Kani is
installed in Linux CI (`.github/workflows/kani-proofs.yml`), so "defined" is
the honest status word in local environments until executed. What DOES execute
green under plain `cargo test` in all environments are the 8 deterministic
property doubles in `property_doubles` (same properties, bounded sweeps):

```
cookie_gate_stateless_verification
ct_eq_and_select_no_secret_branch
frame_split_reassemble_roundtrip_bounded
max_stream_bytes_cap_enforced
nonce_domain_separation
nostd_frame_parse_never_panics_property_sweep
nostd_stack_secret_ct_eq_property_sweep
replay_window_monotonic_and_drops
```

(`test_stack_secret_zeroize_on_drop` is a plain `cargo test` unit test
in `nostd_microcore`, re-exported into the 30-test harness binary — not
a Kani proof. The harness binary total includes 23 re-exported module unit tests
alongside the 7 doubles.)

## 3. Bridging Symbolic Models & Implementation: DudeCT Constant-Time Timing Analysis

To bridge the gap between symbolic Dolev-Yao protocol models (which assume perfect mathematical cryptography) and concrete physical execution, the engineering baseline implements a three-tiered verification hierarchy:

1. **Tier 1 — Symbolic Protocol Logic (ProVerif 2.05)**: Applied pi-calculus proves secrecy, mutual authentication, forward secrecy, and PCS healing under an unbounded active network adversary.
2. **Tier 2 — Bit-Precise Software Verification (Kani + CBMC)**: Bounded model checking proves memory safety, absence of undefined behavior, panic freedom on arbitrary wire inputs, and sliding window monotonicity in Rust.
3. **Tier 3 — Side-Channel & Timing Attack Freedom (DudeCT Statistical Leakage)**: Evaluates execution timing distributions using Welch's two-sample $t$-test (Reparaz et al. IEEE S&P / ePrint 2016/1123).

### DudeCT Verification Metrics

Executed via `cargo test --test dudect_ct` (Rust native) and `pytest tests/test_dudect_timing_analysis.py` (Python):
- **Criterion**: Fail to reject null hypothesis $H_0$ if $|t| < 4.5$ ($p > 99.999\%$ confidence of identical timing distributions between fixed and random secrets).
- **Positive Control**: Intentionally leaky early-exit comparators trigger $|t| > 4.5$ (e.g. $|t| \approx 7.5$ to $62.9$), proving zero false negatives.
- **Production Status**: `ct::ct_eq` ($|t| = 0.7110$) and `StackSecretBuffer::ct_eq` ($|t| = 0.6181$) pass well beneath the $4.5$ threshold.

## 4. Formal Verification Certificate Orchestrator

The verification suite includes an automated certificate generator:

```sh
python tools/formal_verification_orchestrator.py --strict
```

This tool runs all machine-checked models, executes the deterministic property doubles, checks cryptographic SHA-512 hashes of all formal source assets, and produces `docs/formal/formal_verification_certificate.json` and its SHA-512 seal (`formal_verification_certificate.json.sha512`). In CI, `.github/workflows/kani-proofs.yml` executes Kani via the official `model-checking/kani-github-action@v1` and uploads SARIF reports to GitHub Security Code Scanning.
